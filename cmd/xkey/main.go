package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/console"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
	"github.com/pborman/uuid"
)

var (
	txFromFile bool
	eip155     bool
	brainSrc   bool
	extended   bool
	plaintext  bool
)

func main() {
	if len(os.Args) > 1 {
		flags := os.Args[1]
		if strings.Contains(flags, "h") {
			help()
			return
		}
		if strings.Contains(flags, "?") {
			help()
			return
		}
		if strings.Contains(flags, "t") {
			test()
			return
		}
		if strings.Contains(flags, "i") {
			ImportBrainWallet()
			return
		}

		if strings.Contains(flags, "x") {
			extended = true
		}
		if strings.Contains(flags, "n") {
			eip155 = true
		}
		if strings.Contains(flags, "f") {
			txFromFile = true
		}
		if strings.Contains(flags, "b") {
			brainSrc = true
		}
		if strings.Contains(flags, "p") {
			plaintext = confirmPlainTextMode()
		}
	}
	run()
}

func help() {
	fmt.Println("xkey v.0.3")
	fmt.Println("USAGE: xkey [flags]")
	fmt.Println("\t h - help")
	fmt.Println("\t i - import brainwallet")
	fmt.Println("\t b - use brainwallet")
	fmt.Println("\t n - use network id")
	fmt.Println("\t f - tx from file")
	fmt.Println("\t x - extended input")
	fmt.Println("\t p - plaintext input")
	fmt.Println("\t t - test")
}

func confirmPlainTextMode() bool {
	s := getString("Do you really want the plain text mode? ")
	return s[0] == 'y'
}

func getInt(text string) int {
	fmt.Print(text)
	var n int
	for {
		_, err := fmt.Scanf("%d", &n)
		if err != nil {
			fmt.Printf("error [%s], please try again \n", err)
		} else {
			break
		}
	}
	return n
}

func getString(text string) string {
	fmt.Print(text)
	var s []byte
	for {
		s = terminal.PlainTextInput()
		if s == nil {
			fmt.Print("please try again: ")
		} else {
			break
		}
	}
	return string(s)
}

func getSigner() types.Signer {
	if eip155 {
		n := getInt("Please enter the chain id: ")
		x := big.NewInt(int64(n))
		return types.NewEIP155Signer(x)
	} else {
		return types.HomesteadSigner{}
	}
}

func secureInputWithConfirmations(confirmations int) []byte {
	s := terminal.SecureInput(extended)
	for i := 0; i < confirmations; i++ {
		fmt.Print("Please confirm: ")
		if !plaintext {
			fmt.Println()
		}
		x := terminal.SecureInput(extended)
		if !bytes.Equal(s, x) {
			fmt.Printf("Failed confirmation #%d. Let's try again from scratch.\n", i)
			return nil
		}
	}
	return s
}

func ImportBrainWallet() {
	c := getInt("Please enter the number of BW confirmations: ")
	key := bip39toKey(c)

	c = getInt("Please enter the number of password confirmations: ")
	fmt.Println("Please enter the password for key encryption")
	var pass []byte
	for pass == nil {
		pass = secureInputWithConfirmations(c)
	}

	keyjson, err := keystore.EncryptKey(key, string(pass), keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		utils.Fatalf("Error encrypting key: %v", err)
	}

	// store the file to disk
	rnd := make([]byte, 16)
	err = crutils.StochasticRand(rnd)
	if err != nil {
		utils.Fatalf("Failed to generate random data: %s", err)
	}

	name := fmt.Sprintf("./tmp/%x-%x", key.Address, rnd)
	_, err = os.Stat(name)
	if !os.IsNotExist(err) {
		utils.Fatalf("Unexpected error: file [%s] already exist", name)
	}

	if err := ioutil.WriteFile(name, keyjson, 0666); err != nil {
		utils.Fatalf("Failed to write keyfile to [%s]: %v", name, err)
	}

	fmt.Printf("new address: %x \n", key.Address)
	fmt.Println("key file: ", name)
}

// do not delete
//func findFileByAddress(src common.Address) string {
//	address := fmt.Sprintf("%x", src)
//	usr, err := user.Current()
//	if err != nil {
//		utils.Fatalf("can not find current user: %s", err)
//	}
//	dir := usr.HomeDir + "/.ethereum/keystore/"
//	files, err := ioutil.ReadDir(dir)
//	if err != nil {
//		utils.Fatalf("can not read directory: %s", err)
//	}
//
//	for _, f := range files {
//		if strings.Contains(f.Name(), address) {
//			return dir + f.Name()
//		}
//	}
//
//	fmt.Println("key file not found, please enter file name:")
//	name := terminal.PlainTextInput()
//	if len(name) == 0 {
//		utils.Fatalf("key file is missing")
//	}
//	return string(name)
//}

func checkTxParams(args *ethapi.SendTxArgs) {
	if args.Nonce == nil {
		utils.Fatalf("Invalid tx: nonce is nil")
	}
	if args.To == nil {
		utils.Fatalf("Invalid tx: [to] is nil")
	}
	if args.Gas == nil {
		utils.Fatalf("Invalid tx: gas is nil")
	}
}

func createTransaction(args *ethapi.SendTxArgs) *types.Transaction {
	checkTxParams(args)
	var input []byte
	if args.Data != nil {
		input = *args.Data
	} else if args.Input != nil {
		input = *args.Input
	}
	if args.To == nil {
		return types.NewContractCreation(uint64(*args.Nonce), (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
	}
	return types.NewTransaction(uint64(*args.Nonce), *args.To, (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
}

func requestTransaction() *ethapi.SendTxArgs {
	var tb []byte
	var err error
	if txFromFile {
		fname := getString("Please enter tx file name: ")
		tb, err = ioutil.ReadFile(fname)
		if err != nil {
			utils.Fatalf("Failed to read the tx file [%s]: %v", fname, err)
		}
	} else {
		ts := getString("Please enter tx for signing: ")
		tb = []byte(ts)
	}

	var txArgs ethapi.SendTxArgs
	if err = json.Unmarshal(tb, &txArgs); err != nil {
		utils.Fatalf("tx unmarshal failed: %s", err)
	}
	if txArgs.Input == nil && txArgs.Data != nil {
		txArgs.Input = txArgs.Data
	}
	return &txArgs
}

func getTransaction() *types.Transaction {
	txArgs := requestTransaction()
	tx := createTransaction(txArgs)
	return tx
}

func getPassword() string {
	if plaintext {
		pass, err := console.Stdin.PromptPassword("Please enter password: ")
		if err != nil {
			utils.Fatalf("Failed to read passphrase: %v", err)
		}
		return pass
	}

	p := terminal.SecureInput(extended)
	return string(p)
}

func bip39toKey(confirmations int) *keystore.Key {
	var brainwallet []byte
	for brainwallet == nil {
		brainwallet = secureInputWithConfirmations(confirmations)
	}
	hash := crutils.Sha2(brainwallet)
	privateKey, err := crypto.ToECDSA(hash)
	if err != nil {
		utils.Fatalf("brain wallet derivation error: %v", err)
	}

	id := uuid.NewRandom()
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
		PrivateKey: privateKey,
	}

	return key
}

func getKeyFromFile() *keystore.Key {
	//keyfile := findFileByAddress(gTxArgs.From) // do not delete
	keyfile := getString("Please enter the key file name: ")
	keyjson, err := ioutil.ReadFile(keyfile)
	if err != nil {
		utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfile, err)
	}

	passphrase := getPassword()
	key, err := keystore.DecryptKey(keyjson, string(passphrase))
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}
	return key
}

func getKey() *keystore.Key {
	if brainSrc {
		return bip39toKey(0)
	} else {
		return getKeyFromFile()
	}
}

func run() {
	signer := getSigner()
	tx := getTransaction()
	key := getKey()

	signedTX, err := types.SignTx(tx, signer, key.PrivateKey)
	if err != nil {
		utils.Fatalf("Signing error: %s", err)
	}

	res, err := rlp.EncodeToBytes(signedTX)
	if err != nil {
		utils.Fatalf("EncodeRLP error: %s", err)
	}

	fmt.Printf("%x\n", res)
}

func test() {
	fmt.Println("test success")
}
