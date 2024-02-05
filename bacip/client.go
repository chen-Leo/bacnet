// Package bacip implements a Bacnet/IP client
package bacip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/chen-Leo/bacnet"
)

type Client struct {
	ipAddress        net.IP //bacnet broadcast message source ip address
	broadcastAddress net.IP //use this broadcast address to send bacnet messages
	udpPort          int    //bacnet message udp listening port
	udp              *net.UDPConn
	subscriptions    *Subscriptions
	transactions     *Transactions
	Logger           Logger

	stopSign chan bool //stop the listen sign chan
}

type Logger interface {
	Info(...interface{})
	Error(...interface{})
}

type NoOpLogger struct{}

func (NoOpLogger) Info(...interface{})  {}
func (NoOpLogger) Error(...interface{}) {}

type Subscriptions struct {
	sync.RWMutex
	f func(BVLC, net.UDPAddr)
}

const DefaultUDPPort = 47808

func broadcastAddr(n *net.IPNet) (net.IP, error) {
	if n.IP.To4() == nil {
		return net.IP{}, errors.New("does not support IPv6 addresses")
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip, nil
}

// NewClient creates a new bacnet client. It binds on the given port
// and network interface (eth0 for example). If Port is 0, the default
// bacnet port (47808) is used
func NewClient(netInterface string, port int) (*Client, error) {
	c := &Client{subscriptions: &Subscriptions{}, transactions: NewTransactions(), Logger: NoOpLogger{}}

	//Set the broadcast Address and source IP address of the bacnet broadcast message through the netInterface name
	i, err := net.InterfaceByName(netInterface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", netInterface, err)
	}
	if port == 0 {
		port = DefaultUDPPort
	}
	c.udpPort = port
	adders, err := i.Addrs()
	if err != nil {
		return nil, err
	}
	if len(adders) == 0 {
		return nil, fmt.Errorf("interface %s has no addresses", netInterface)
	}

	// todo .....................
	for _, adr := range adders {
		ip, ipNet, err := net.ParseCIDR(adr.String())
		if err != nil {
			return nil, err
		}
		// To4 is nil when type is ip6
		if ip.To4() != nil {
			broadcast, err := broadcastAddr(ipNet)
			if err != nil {
				return nil, err
			}
			c.ipAddress = ip.To4()
			c.broadcastAddress = broadcast
			break
		}
	}
	if c.ipAddress == nil {
		return nil, fmt.Errorf("no IPv4 address assigned to interface ")
	}

	//Establish an udp connection and listen to bacnet messages
	if port == 0 {
		port = DefaultUDPPort
	}
	c.udpPort = port
	c.udp, err = net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: c.udpPort,
	})
	if err != nil {
		return nil, err
	}

	go c.listen()
	return c, nil
}

// NewClientNoNetInterface
// create a new bacnet client, use the default port 47808, listen to bacnet messages at 0.0.0.0:47808
// and do not specify the IpAddress and broadcastAddress when sending messages
func NewClientNoNetInterface(port int) (*Client, error) {
	c := &Client{subscriptions: &Subscriptions{}, transactions: NewTransactions(), Logger: NoOpLogger{}}
	if port > 0 {
		c.udpPort = port
	} else {
		c.udpPort = DefaultUDPPort
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: c.udpPort,
	})
	if err != nil {
		return nil, err
	}
	c.udp = conn
	go c.listen()
	return c, nil
}

// StopListen
// stop listen for incoming bacnet packets.
func (c *Client) StopListen() {
	if c.stopSign != nil {
		c.stopSign <- false
	}
}

func (c *Client) WhoIs(data WhoIs, timeout time.Duration) ([]bacnet.Device, error) {
	npdu := NPDU{
		Version:               Version1,
		IsNetworkLayerMessage: false,
		ExpectingReply:        false,
		Priority:              Normal,
		Destination:           nil,
		Source:                nil,
		ADPU: &APDU{
			DataType:    UnconfirmedServiceRequest,
			ServiceType: ServiceUnconfirmedWhoIs,
			Payload:     &data,
		},
	}

	rChan := make(chan struct {
		bvlc BVLC
		src  net.UDPAddr
	})
	c.subscriptions.Lock()
	//TODO:  add errgroup ?, ensure all f are done and not blocked
	c.subscriptions.f = func(bvlc BVLC, src net.UDPAddr) {
		rChan <- struct {
			bvlc BVLC
			src  net.UDPAddr
		}{
			bvlc: bvlc,
			src:  src,
		}
	}
	c.subscriptions.Unlock()
	defer func() {
		c.subscriptions.f = nil
	}()
	_, err := c.broadcast(npdu)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	//Use a set to deduplicate results

	set := map[Iam]bacnet.Address{} //接受返回消息
	for {
		select {
		case <-timer.C:
			var result []bacnet.Device
			for iam, addr := range set {
				result = append(result, bacnet.Device{
					ID:           iam.ObjectID,
					MaxApdu:      iam.MaxApduLength,
					Segmentation: iam.SegmentationSupport,
					Vendor:       iam.VendorID,
					Addr:         addr,
				})
			}
			return result, nil
		case r := <-rChan:
			//clean/filter  network answers here
			apdu := r.bvlc.NPDU.ADPU
			if apdu != nil {
				if apdu.DataType == UnconfirmedServiceRequest &&
					apdu.ServiceType == ServiceUnconfirmedIAm {
					iam, ok := apdu.Payload.(*Iam)
					if !ok {
						return nil, fmt.Errorf("unexpected payload type %T", apdu.Payload)
					}
					//fmt.Printf("id  %v\n", iam.ObjectID.Instance)
					//Only add result that we are interested in. Well
					//behaved devices should not answer if their
					//InstanceID isn't in the given range. But because
					//the IAM response is in broadcast mode, we might
					//receive an answer triggered by an other whois
					if data.High != nil && data.Low != nil {
						if iam.ObjectID.Instance >= bacnet.ObjectInstance(*data.Low) &&
							iam.ObjectID.Instance <= bacnet.ObjectInstance(*data.High) {
							addr := bacnet.AddressFromUDP(r.src)
							if r.bvlc.NPDU.Source != nil {
								addr.Net = r.bvlc.NPDU.Source.Net
								addr.Adr = r.bvlc.NPDU.Source.Adr
							}
							set[*iam] = *addr
						}
					} else {
						addr := bacnet.AddressFromUDP(r.src)
						if r.bvlc.NPDU.Source != nil {
							addr.Net = r.bvlc.NPDU.Source.Net
							addr.Adr = r.bvlc.NPDU.Source.Adr
						}
						set[*iam] = *addr
					}
				}
			}
		}
	}
}

// WhoIsWithNetInterface 向指定网卡发送WhoIs消息，传入的adr形如"192.0.2.0/24"形式,Client的默认IpAddress，BroadcastAddress会变成指定网卡的ip及broadcast
func (c *Client) WhoIsWithNetInterface(ip net.IP, ipNet *net.IPNet, data WhoIs, timeout time.Duration) ([]bacnet.Device, error) {
	// To4 is nil when type is ip6
	if ip.To4() != nil {
		broadcast, err := broadcastAddr(ipNet)
		if err != nil {
			return nil, err
		}
		c.ipAddress = ip.To4()
		c.broadcastAddress = broadcast
	} else {
		return nil, fmt.Errorf("no IPv4 address assigned to interface ")
	}
	return c.WhoIs(data, timeout)
}

func (c *Client) ReadProperty(ctx context.Context, device bacnet.Device, readProp ReadProperty) (interface{}, error) {
	invokeID := c.transactions.GetID()
	defer c.transactions.FreeID(invokeID)
	npdu := NPDU{
		Version:               Version1,
		IsNetworkLayerMessage: false,
		ExpectingReply:        true,
		Priority:              Normal,
		Destination:           &device.Addr,
		Source: bacnet.AddressFromUDP(net.UDPAddr{
			IP:   c.ipAddress,
			Port: c.udpPort,
		}),
		HopCount: 255,
		ADPU: &APDU{
			DataType:    ConfirmedServiceRequest,
			ServiceType: ServiceConfirmedReadProperty,
			InvokeID:    invokeID,
			Payload:     &readProp,
		},
	}
	rChan := make(chan APDU)
	c.transactions.SetTransaction(invokeID, rChan, ctx)
	defer c.transactions.StopTransaction(invokeID)
	_, err := c.send(npdu)
	if err != nil {
		return nil, err
	}
	select {
	case apdu := <-rChan:
		//Todo: ensure response validity, ensure conversion cannot panic
		if apdu.DataType == Error {
			return nil, *apdu.Payload.(*ApduError)
		}
		if apdu.DataType == ComplexAck && apdu.ServiceType == ServiceConfirmedReadProperty {
			data := apdu.Payload.(*ReadProperty).Data
			return data, nil
		}
		return nil, errors.New("invalid answer")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReadPropertyWithNetInterface 向指定网卡发送read消息，传入的adr形如"192.0.2.0/24"形式,Client的默认IpAddress，BroadcastAddress会变成指定网卡的ip及broadcast
func (c *Client) ReadPropertyWithNetInterface(ip net.IP, ipNet *net.IPNet, ctx context.Context, device bacnet.Device, readProp ReadProperty) (interface{}, error) {
	// To4 is nil when type is ip6
	if ip.To4() != nil {
		broadcast, err := broadcastAddr(ipNet)
		if err != nil {
			return nil, err
		}
		c.ipAddress = ip.To4()
		c.broadcastAddress = broadcast
	} else {
		return nil, fmt.Errorf("no IPv4 address assigned to interface ")
	}
	return c.ReadProperty(ctx, device, readProp)
}

func (c *Client) WriteProperty(ctx context.Context, device bacnet.Device, writeProp WriteProperty) error {
	invokeID := c.transactions.GetID()
	defer c.transactions.FreeID(invokeID)
	npdu := NPDU{
		Version:               Version1,
		IsNetworkLayerMessage: false,
		ExpectingReply:        true,
		Priority:              Normal,
		Destination:           &device.Addr,
		Source: bacnet.AddressFromUDP(net.UDPAddr{
			IP:   c.ipAddress,
			Port: c.udpPort,
		}),
		HopCount: 255,
		ADPU: &APDU{
			DataType:    ConfirmedServiceRequest,
			ServiceType: ServiceConfirmedWriteProperty,
			InvokeID:    invokeID,
			Payload:     &writeProp,
		},
	}
	wrChan := make(chan APDU)
	c.transactions.SetTransaction(invokeID, wrChan, ctx)
	defer c.transactions.StopTransaction(invokeID)
	_, err := c.send(npdu)
	if err != nil {
		return err
	}

	select {
	case apdu := <-wrChan:
		//Todo: ensure response validity, ensure conversion cannot panic
		if apdu.DataType == Error {
			return *apdu.Payload.(*ApduError)
		}
		if apdu.DataType == SimpleAck && apdu.ServiceType == ServiceConfirmedWriteProperty {
			return nil
		}
		return errors.New("invalid answer")
	case <-ctx.Done():
		return ctx.Err()
	}

}

// WritePropertyWithNetInterface 向指定网卡发送write消息，传入的adr形如"192.0.2.0/24"形式，Client的默认IpAddress，BroadcastAddress会变成指定网卡的ip及broadcast
func (c *Client) WritePropertyWithNetInterface(ip net.IP, ipNet *net.IPNet, ctx context.Context, device bacnet.Device, writeProp WriteProperty) error {
	// To4 is nil when type is ip6
	if ip.To4() != nil {
		broadcast, err := broadcastAddr(ipNet)
		if err != nil {
			return err
		}
		c.ipAddress = ip.To4()
		c.broadcastAddress = broadcast
	} else {
		return fmt.Errorf("no IPv4 address assigned to interface ")
	}
	return c.WriteProperty(ctx, device, writeProp)
}

// listen for incoming bacnet packets.
// Exit the function when a message is received from the stopSign, don't care what the message is
func (c *Client) listen() {
	c.stopSign = make(chan bool)
	for {
		select {
		case <-c.stopSign:
			c.stopSign = nil
			return
		default:
			b := make([]byte, 2048)
			i, addr, err := c.udp.ReadFromUDP(b)
			if err != nil {
				c.Logger.Error(err.Error())
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						c.Logger.Error("panic in handle message: ", r)
					}
				}()
				err := c.handleMessage(addr, b[:i])
				if err != nil {
					c.Logger.Error("handle msg: ", err)
				}
			}()
		}
	}
}

// handleMessage
func (c *Client) handleMessage(src *net.UDPAddr, b []byte) error {
	var bvlc BVLC
	err := bvlc.UnmarshalBinary(b)
	if err != nil && errors.Is(err, ErrNotBAcnetIP) {
		return err
	}
	apdu := bvlc.NPDU.ADPU
	if apdu == nil {
		c.Logger.Info(fmt.Sprintf("Received network packet %+v", bvlc.NPDU))
		return nil
	}
	c.subscriptions.RLock()
	if c.subscriptions.f != nil {
		//If f block, there is a deadlock here
		c.subscriptions.f(bvlc, *src)
	}
	c.subscriptions.RUnlock()
	if apdu.DataType == ComplexAck || apdu.DataType == SimpleAck || apdu.DataType == Error {
		invokeID := bvlc.NPDU.ADPU.InvokeID
		tx, ok := c.transactions.GetTransaction(invokeID)
		if !ok {
			return fmt.Errorf("no transaction found for id %d", invokeID)
		}
		select {
		case tx.APDU <- *apdu:
			return nil
		case <-tx.Ctx.Done():
			return fmt.Errorf("handler for tx %d: %w", invokeID, tx.Ctx.Err())
		}
	}
	return nil
}

func (c *Client) send(npdu NPDU) (int, error) {
	bytes, err := BVLC{
		Type:     TypeBacnetIP,
		Function: BacFuncUnicast,
		NPDU:     npdu,
	}.MarshalBinary()
	if err != nil {
		return 0, err
	}
	if npdu.Destination == nil {
		return 0, fmt.Errorf("destination bacnet address should be not nil to send unicast")
	}
	addr := bacnet.UDPFromAddress(*npdu.Destination)

	return c.udp.WriteToUDP(bytes, &addr)

}

func (c *Client) broadcast(npdu NPDU) (int, error) {
	bytes, err := BVLC{
		Type:     TypeBacnetIP,
		Function: BacFuncBroadcast,
		NPDU:     npdu,
	}.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return c.udp.WriteToUDP(bytes, &net.UDPAddr{
		IP:   c.broadcastAddress,
		Port: c.udpPort,
	})
}
