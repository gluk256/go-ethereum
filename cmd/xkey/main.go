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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
	"github.com/pborman/uuid"
)

var (
	txFromFile   bool
	eip155       bool
	brainSrc     bool
	extended     bool
	plaintext    bool
	saveSignedTx bool
)

func main() {
	defer crutils.ProveDataDestruction()
	if len(os.Args) > 1 {
		done := processFlags(os.Args[1])
		if done {
			return
		}
	}
	run()
}

// returns true if execution is complete
func processFlags(flags string) bool {
	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		return true
	}
	if strings.Contains(flags, "t") {
		test()
		return true
	}
	if strings.Contains(flags, "i") {
		ImportBrainWallet()
		return true
	}

	extended = strings.Contains(flags, "x")
	eip155 = strings.Contains(flags, "n")
	txFromFile = strings.Contains(flags, "f")
	brainSrc = strings.Contains(flags, "b")
	saveSignedTx = strings.Contains(flags, "s")
	if strings.Contains(flags, "p") {
		plaintext = confirmPlainTextMode()
	}
	return false
}

func help() {
	fmt.Println("xkey v.0.5")
	fmt.Println("USAGE: xkey [flags]")
	fmt.Println("\t h - help")
	fmt.Println("\t i - import brainwallet")
	fmt.Println("\t b - use brainwallet")
	fmt.Println("\t n - use network id")
	fmt.Println("\t f - tx from file")
	fmt.Println("\t x - extended input")
	fmt.Println("\t p - plaintext input")
	fmt.Println("\t s - save signed tx to file")
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

func isInputValid(s []byte) bool {
	if len(s) < 2 {
		fmt.Println("User requested exit.")
		return false
	}
	if len(s) < 12 {
		fmt.Println("Warning: password is too short!")
	}
	return true
}

func secureInputWithConfirmations(confirmations int) []byte {
	s := terminal.SecureInput(extended)
	if !isInputValid(s) {
		return nil
	}
	for i := 0; i < confirmations; i++ {
		fmt.Print("Please confirm: ")
		if !plaintext {
			fmt.Println()
		}
		x := terminal.SecureInput(extended)
		valid := isInputValid(x)
		equal := bytes.Equal(s, x)
		crutils.AnnihilateData(x)
		if !valid || !equal {
			fmt.Printf("Failed confirmation #%d. Let's try again from scratch.\n", i)
			return nil
		}
	}
	return s
}

func ImportBrainWallet() {
	c := getInt("Please enter the number of BW confirmations: ")
	key := bip39toKey(c)
	defer asym.AnnihilatePrivateKey(key.PrivateKey)
	fmt.Printf("new address: %x \n", key.Address)
	c = getInt("Please enter the number of password confirmations: ")
	fmt.Println("Please enter the password for key encryption")

	var pass []byte
	defer crutils.AnnihilateData(pass)
	for j := 0; pass == nil; j++ {
		pass = secureInputWithConfirmations(c)
		if j >= 3 {
			fmt.Println("Failed after three retries. Exit.")
			return
		}
	}

	keyjson, err := keystore.EncryptKey(key, string(pass), keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		fmt.Printf("Error encrypting key: %s\n", err.Error())
		return
	}

	prefix := fmt.Sprintf("%x", key.Address)
	serializeContent(prefix, keyjson)
}

func serializeContent(prefix string, content []byte) {
	var name string
	for i := 0; i < 1024; i++ {
		rnd := make([]byte, 4)
		crutils.Randomize(rnd)
		name = fmt.Sprintf("./%s-%x", prefix, rnd)
		_, err := os.Stat(name)
		if os.IsNotExist(err) {
			break
		}
	}

	err := ioutil.WriteFile(name, content, 0666)
	if err == nil {
		fmt.Println("saved result to the file: ", name)
	} else {
		fmt.Printf("Failed to write keyfile to [%s]: %s\n", name, err.Error())
	}
}

func checkTxParams(args *ethapi.SendTxArgs) bool {
	if args.Nonce == nil {
		fmt.Printf("Invalid tx: nonce is missing\n")
		return false
	}
	if args.To == nil {
		fmt.Printf("Invalid tx: [to] is missing\n")
		return false
	}
	if args.Gas == nil {
		fmt.Printf("Invalid tx: gas is missing\n")
		return false
	}
	if args.GasPrice == nil {
		fmt.Printf("Invalid tx: gas price is missing\n")
		return false
	}
	if args.Value == nil {
		fmt.Printf("Invalid tx: value is missing\n")
		return false
	}
	return true
}

func createTransaction(args *ethapi.SendTxArgs) *types.Transaction {
	if !checkTxParams(args) {
		return nil
	}
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
			fmt.Printf("Failed to read the tx file [%s]: %s\n", fname, err.Error())
			return nil
		}
	} else {
		ts := getString("Please enter tx for signing: ")
		tb = []byte(ts)
	}

	var txArgs ethapi.SendTxArgs
	if err = json.Unmarshal(tb, &txArgs); err != nil {
		fmt.Printf("tx unmarshal failed: %s\n", err)
		return nil
	}
	if txArgs.Input == nil && txArgs.Data != nil {
		txArgs.Input = txArgs.Data
	}
	return &txArgs
}

func getTransaction() (tx *types.Transaction) {
	txArgs := requestTransaction()
	if txArgs != nil {
		tx = createTransaction(txArgs)
	}
	return tx
}

func getPassword() (p []byte) {
	if plaintext {
		p = terminal.PasswordModeInput()
	} else {
		p = terminal.SecureInput(extended)
	}
	return p
}

func bip39toKey(confirmations int) *keystore.Key {
	var brainwallet []byte
	defer crutils.AnnihilateData(brainwallet)
	for j := 0; brainwallet == nil; j++ {
		brainwallet = secureInputWithConfirmations(confirmations)
		if j >= 3 {
			fmt.Println("Failed after three retries. Exit.")
			return nil
		}
	}
	hash := crutils.Sha2(brainwallet)
	defer crutils.AnnihilateData(hash)
	privateKey, err := crypto.ToECDSA(hash)
	if err != nil {
		fmt.Printf("failed to derive the wallet: %s\n", err.Error())
		return nil
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
		fmt.Printf("Failed to read the keyfile at '%s': %s\n", keyfile, err.Error())
		return nil
	}

	pass := getPassword()
	defer crutils.AnnihilateData(pass)
	key, err := keystore.DecryptKey(keyjson, string(pass))
	if err != nil {
		fmt.Printf("Error decrypting key: %s\n", err.Error())
		return nil
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
	if tx == nil {
		return
	}

	key := getKey()
	defer asym.AnnihilatePrivateKey(key.PrivateKey)
	if key == nil {
		return
	}

	signedTx, err := types.SignTx(tx, signer, key.PrivateKey)
	if err != nil {
		fmt.Printf("Signing error: %s\n", err.Error())
		return
	}

	res, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		fmt.Printf("EncodeRLP error: %s\n", err.Error())
		return
	}

	publishSinedTx(res)
}

func publishSinedTx(res []byte) {
	s := fmt.Sprintf("%x\n", res)
	fmt.Print(s)
	if saveSignedTx {
		serializeContent("tx", []byte(s))
	}
}

func test() {
	fmt.Println("test success")
}

// do not delete!
// func findFileByAddress(src common.Address) string {
// 	address := fmt.Sprintf("%x", src)
// 	usr, err := user.Current()
// 	if err != nil {
// 		fmt.Printf("can not find current user: %s\n", err.Error())
// 		return "FileNotFound"
// 	}
// 	dir := usr.HomeDir + "/.ethereum/keystore/"
// 	files, err := ioutil.ReadDir(dir)
// 	if err != nil {
// 		fmt.Printf("can not read directory: %s\n", err.Error())
// 		return "FileNotFound"
// 	}
// 	for _, f := range files {
// 		if strings.Contains(f.Name(), address) {
// 			return dir + f.Name()
// 		}
// 	}
// 	fmt.Println("key file not found, please enter file name:")
// 	name := terminal.PlainTextInput()
// 	if len(name) == 0 {
// 		fmt.Println("key file is missing")
// 		return "FileNotFound"
// 	}
// 	return string(name)
// }
