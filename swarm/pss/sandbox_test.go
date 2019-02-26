package pss

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/simulations"
	"github.com/ethereum/go-ethereum/p2p/simulations/adapters"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/swarm/network"
	"github.com/ethereum/go-ethereum/swarm/network/simulation"
	"github.com/ethereum/go-ethereum/swarm/pot"
	"github.com/ethereum/go-ethereum/swarm/state"
)

var (
	runNodes      = flag.Int("nodes", 0, "nodes to start in the network")
	runMessages   = flag.Int("messages", 0, "messages to send during test")

	topic = BytesToTopic([]byte{0x00, 0x00, 0x06, 0x82})
	handlerC = make(chan handlerNotification) // passes message from pss message handler to simulation driver
	handlerDone bool // set to true on termination of the simulation run
	mu = &sync.Mutex{} // keeps handlerDonc in sync
	kademlias = make(map[enode.ID]*network.Kademlia)
	nodeAddrs = make(map[enode.ID][]byte) // make predictable overlay addresses from the generated random enode ids
	msgsToReceive int // total count of messages to receive, used for terminating the simulation run
	recipients = make(map[int][]enode.ID) // for logging output only
	msgs [][]byte // recipient addresses of messages
	expectedMsgs = make(map[enode.ID][]uint64) // message serials we expect respective nodes to receive
	senders = make(map[int]enode.ID) // originating nodes of the messages (intention is to choose as far as possible from the receiving neighborhood)
	pof = pot.DefaultPof(256) // generate messages and index them
	sim *simulation.Simulation
	doneC = make(chan struct{}) // terminates the handler channel listener
	errC = make(chan error) // error to pass to main sim thread
	msgC = make(chan handlerNotification) // message receipt notification to main sim thread
)

// needed to make the enode id of the receiving node available to the handler for triggers
type handlerContextFunc func(*adapters.NodeConfig) *handler

// struct to notify reception of messages to simulation driver
// TODO To make code cleaner:
// - consider a separate pss unwrap to message event in sim framework (this will make eventual message propagation analysis with pss easier/possible in the future)
// - consider also test api calls to inspect handling results of messages
type handlerNotification struct {
	id     enode.ID
	serial uint64
}

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
}

func isDone() bool {
	mu.Lock()
	defer mu.Unlock()
	return handlerDone
}

func setDone() {
	mu.Lock()
	defer mu.Unlock()
	handlerDone = true
}

func TestSandbox(t *testing.T) {
	if (*runNodes > 0 && *runMessages == 0) || (*runMessages > 0 && *runNodes == 0) {
		t.Fatal("cannot specify only one of flags --nodes and --messages")
	} else if *runNodes > 0 {
		t.Run(fmt.Sprintf("%d/%d", *runMessages, *runNodes), testProxNetwork)
	} else {
		t.Run("1/4", testProxNetwork)
	}
}

func getCmdParams(t *testing.T) (int, int) {
	args := strings.Split(t.Name(), "/")
	msgCount, err := strconv.ParseInt(args[1], 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	nodeCount, err := strconv.ParseInt(args[2], 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return int(msgCount), int(nodeCount)
}

// message handler for pss
func getHandler(ctx *adapters.NodeConfig) *handler {
	return &handler{
		f: func(msg []byte, p *p2p.Peer, asymmetric bool, keyid string) error {
			// using simple serial in message body, makes it easy to keep track of who's getting what
			serial, c := binary.Uvarint(msg)
			if c <= 0 {
				log.Crit(fmt.Sprintf("corrupt message received by %x (uvarint parse returned %d)", ctx.ID, c))
			}

			if isDone() {
				return errors.New("handlers aborted") // terminate if simulation is over
			}

			// pass message context to the listener in the simulation
			handlerC <- handlerNotification{
				id:     ctx.ID,
				serial: serial,
			}
			return nil
		},
		caps: &handlerCaps{
			raw:  true, // we use raw messages for simplicity
			prox: true,
		},
	}
}

func readSnapshot(t *testing.T, nodeCount int) simulations.Snapshot {
	f, err := os.Open(fmt.Sprintf("testdata/snapshot_%d.json", nodeCount))
	if err != nil {
		t.Fatal(err)
	}
	jsonbyte, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	var snap simulations.Snapshot
	err = json.Unmarshal(jsonbyte, &snap)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func initTestVariables(sim *simulation.Simulation, msgCount int) {
	for _, nodeId := range sim.NodeIDs() {
		nodeAddrs[nodeId] = nodeIDToAddr(nodeId)
	}

	for i := 0; i < int(msgCount); i++ {
		// we choose message addresses by random
		msgAddr := pot.RandomAddress()
		msgs = append(msgs, msgAddr.Bytes())
		smallestPo := 256

		// loop through all nodes and add the message to receipient indices
		for _, nod := range sim.Net.GetNodes() {
			po, _ := pof(msgs[i], nodeAddrs[nod.ID()], 0)
			depth := kademlias[nod.ID()].NeighbourhoodDepth()

			// node has message address within nearest neighborhood depth, that means it is a recipient
			if po >= depth {
				recipients[i] = append(recipients[i], nod.ID())
				expectedMsgs[nod.ID()] = append(expectedMsgs[nod.ID()], uint64(i))
				msgsToReceive++
			}

			// keep track of the smallest po value in the iteration
			// the first node in the smallest value bin will be the sender
			if po < smallestPo {
				smallestPo = po
				senders[i] = nod.ID()
			}
		}
		log.Debug("nn for msg", "rcptcount", len(recipients[i]), "msgidx", i, "msg", common.Bytes2Hex(msgs[i]), "sender", senders[i], "senderpo", smallestPo)
	}
	log.Debug("msgs to receive", "count", msgsToReceive)
}

// This tests generates a sequenced number of messages with random addresses.
// It then calculates which nodes in the network have the address of each message
// within their nearest neighborhood depth, and stores them as recipients.
// Upon sending the messages, it verifies that the respective message is passed to the message handlers of these recipients.
// It will fail if a recipient handles a message it should not, or if after propagation not all expected messages are handled (timeout)
func testProxNetwork(t *testing.T) {
	msgCount, nodeCount := getCmdParams(t)
	handlerContextFuncs := make(map[Topic]handlerContextFunc)
	handlerContextFuncs[topic] = getHandler
	services := newProxServices(true, handlerContextFuncs, kademlias)
	snap := readSnapshot(t, nodeCount)
	sim = simulation.New(services)
	defer sim.Close()
	err := sim.Net.Load(&snap)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	initTestVariables(sim, msgCount)
	result := sim.Run(ctx, runFunc)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	t.Logf("completed %d", result.Duration)
}

func sendAllMsgs(msgs [][]byte, senders map[int]enode.ID, sim *simulation.Simulation) {
	for i, msg := range msgs {
		log.Debug("sending msg", "idx", i, "from", senders[i])
		nodeClient, err := sim.Net.GetNode(senders[i]).Client()
		if err != nil {
			log.Crit(err.Error())
		}
		var uvarByte [8]byte
		binary.PutUvarint(uvarByte[:], uint64(i))
		nodeClient.Call(nil, "pss_sendRaw", hexutil.Encode(msg), hexutil.Encode(topic[:]), hexutil.Encode(uvarByte[:]))
	}
}

func runFunc(ctx context.Context, sim *simulation.Simulation) error {
	go handlerChannelListener(ctx, errC, doneC, msgC)
	time.Sleep(64 * time.Millisecond)
	go sendAllMsgs(msgs, senders, sim)
	// collect incoming messages and terminate with corresponding status when message handler listener ends
	msgsCountdown := msgsToReceive
	cnt := 0
	for {
		select {
		case err := <-errC:
			return err
		case hn := <-msgC:
			cnt++
			msgsCountdown--
			log.Debug("msg received", "msgs_received", cnt, "total_expected", msgsToReceive, "id", hn.id, "serial", hn.serial)
			if msgsCountdown == 0 {
				close(doneC)
			}
		}
	}
	return nil
}

func handlerChannelListener(ctx context.Context, errC chan error, doneC chan struct{}, msgC chan handlerNotification) {
	for {
		select {
		case <-doneC: // graceful exit
			setDone()
			errC <- nil
			return

		case <-ctx.Done(): // timeout or cancel
			setDone()
			errC <- ctx.Err()
			return

		// incoming message from pss message handler
		case handlerNotification := <-handlerC:
			// check if recipient has already received all its messages and notify to fail the test if so
			xMsgs := expectedMsgs[handlerNotification.id]
			if len(xMsgs) == 0 {
				setDone()
				errC <- fmt.Errorf("too many messages received by recipient %x", handlerNotification.id)
				return
			}

			// check if message serial is in expected messages for this recipient and notify to fail the test if not
			idx := -1
			for i, msg := range xMsgs {
				if handlerNotification.serial == msg {
					idx = i
					break
				}
			}
			if idx == -1 {
				setDone()
				errC <- fmt.Errorf("message %d received by wrong recipient %v", handlerNotification.serial, handlerNotification.id)
				return
			}

			// message is ok, so remove that message serial from the recipient expectation array and notify the main sim thread
			xMsgs[idx] = xMsgs[len(xMsgs)-1]
			xMsgs = xMsgs[:len(xMsgs)-1]
			msgC <- handlerNotification
		}
	}
}

// an adaptation of the same services setup as in pss_test.go
// replaces pss_test.go when those tests are rewritten to the new swarm/network/simulation package
func newProxServices(allowRaw bool, handlerContextFuncs map[Topic]handlerContextFunc, kademlias map[enode.ID]*network.Kademlia) map[string]simulation.ServiceFunc {
	stateStore := state.NewInmemoryStore()
	kademlia := func(id enode.ID) *network.Kademlia {
		if k, ok := kademlias[id]; ok {
			return k
		}
		params := network.NewKadParams()
		params.MaxBinSize = 3
		params.MinBinSize = 1
		params.MaxRetries = 1000
		params.RetryExponent = 2
		params.RetryInterval = 1000000
		kademlias[id] = network.NewKademlia(id[:], params)
		return kademlias[id]
	}
	return map[string]simulation.ServiceFunc{
		"pss": func(ctx *adapters.ServiceContext, b *sync.Map) (node.Service, func(), error) {
			// execadapter does not exec init()
			initTest()

			// create keys in whisper and set up the pss object
			ctxlocal, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			keys, err := wapi.NewKeyPair(ctxlocal)
			privkey, err := w.GetPrivateKey(keys)
			pssp := NewPssParams().WithPrivateKey(privkey)
			pssp.AllowRaw = allowRaw
			pskad := kademlia(ctx.Config.ID)
			ps, err := NewPss(pskad, pssp)
			if err != nil {
				return nil, nil, err
			}

			// register the handlers we've been passed
			var deregisters []func()
			for tpc, hndlrFunc := range handlerContextFuncs {
				deregisters = append(deregisters, ps.Register(&tpc, hndlrFunc(ctx.Config)))
			}

			// if handshake mode is set, add the controller
			// TODO: This should be hooked to the handshake test file
			if useHandshake {
				SetHandshakeController(ps, NewHandshakeParams())
			}

			// we expose some api calls for cheating
			ps.addAPI(rpc.API{
				Namespace: "psstest",
				Version:   "0.3",
				Service:   NewAPITest(ps),
				Public:    false,
			})

			// return Pss and cleanups
			return ps, func() {
				// run the handler deregister functions in reverse order
				for i := len(deregisters); i > 0; i-- {
					deregisters[i-1]()
				}
			}, nil
		},
		"bzz": func(ctx *adapters.ServiceContext, b *sync.Map) (node.Service, func(), error) {
			// normally translation of enode id to swarm address is concealed by the network package
			// however, we need to keep track of it in the test driver aswell.
			// if the translation in the network package changes, that can cause thiese tests to unpredictably fail
			// therefore we keep a local copy of the translation here
			addr := network.NewAddr(ctx.Config.Node())
			addr.OAddr = nodeIDToAddr(ctx.Config.Node().ID())

			hp := network.NewHiveParams()
			hp.Discovery = false
			config := &network.BzzConfig{
				OverlayAddr:  addr.Over(),
				UnderlayAddr: addr.Under(),
				HiveParams:   hp,
			}
			return network.NewBzz(config, kademlia(ctx.Config.ID), stateStore, nil, nil), nil, nil
		},
	}
}

// makes sure we create the addresses the same way in driver and service setup
func nodeIDToAddr(id enode.ID) []byte {
	return id.Bytes()
}

// temporary function for polling a "stable" network
// stability here means no conns or drops in network within a "serenity" duration
// timeout is max time to wait for a "stable" network
// TODO: remove when replaced with snapshot
func serenityNowPlease(sim *simulation.Simulation, serenity time.Duration, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	eventFilter := simulation.NewPeerEventsFilter().Connect().Drop()
	eventC := sim.PeerEvents(ctx, sim.NodeIDs(), eventFilter)
	timer := time.NewTimer(serenity)
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-eventC:
			timer.Reset(serenity)
		}
	}
}
