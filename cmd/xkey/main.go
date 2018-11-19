package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/user"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/console"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/pborman/uuid"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var (
	txFromFile    bool
	customKeyFile bool
	eip155        bool
	extended      bool
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
		if strings.Contains(flags, "x") {
			extended = true
		}
		if strings.Contains(flags, "n") {
			eip155 = true
		}
		if strings.Contains(flags, "t") {
			txFromFile = true
		}
		if strings.Contains(flags, "k") {
			customKeyFile = true
		}
		if strings.Contains(flags, "i") {
			ImportBrainWallet()
			return
		}
	}
	run(os.Args)
}

func help() {
	fmt.Println("xkey v.0.3")
	fmt.Println("USAGE: xkey [flags] [txfile] [keyfile]")
	fmt.Println("Flags:")
	fmt.Println("\t h - help")
	fmt.Println("\t x - extended input")
	fmt.Println("\t i - import brain wallet")
	fmt.Println("\t n - use network id")
	fmt.Println("\t t - tx from file")
	fmt.Println("\t k - custom key file")
	fmt.Println("Example: xkey -tnk transact.txt key.json")
}

func secureInputWithConfirmations(confirmations int) []byte {
	s := terminal.SecureInput(extended)
	for i := 0; i < confirmations; i++ {
		fmt.Println("Please confirm")
		x := terminal.SecureInput(extended)
		if !bytes.Equal(s, x) {
			fmt.Printf("Failed confirmation #%d. Let's try again from scratch.\n", i)
			return nil
		}
	}
	return s
}

//func bip39toKey(confirmations int) keystore.Key {
//	var brainwallet []byte
//	for brainwallet == nil {
//		brainwallet = secureInputWithConfirmations(0)
//	}
//	hash := crutils.Sha2(brainwallet)
//	privateKey, err := crypto.ToECDSA(hash)
//	if err != nil {
//		utils.Fatalf("brain wallet derivation error: %v", err)
//	}
//
//	id := uuid.NewRandom()
//	key := &keystore.Key{
//		Id:         id,
//		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
//		PrivateKey: privateKey,
//	}
//
//	return key
//}

func ImportBrainWallet() {
	var brainwallet []byte
	for brainwallet == nil {
		brainwallet = secureInputWithConfirmations(0)
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

	fmt.Println("Please enter the password for key encryption")
	var pass []byte
	for pass == nil {
		pass = secureInputWithConfirmations(0)
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

	if err := ioutil.WriteFile(name, keyjson, 0770); err != nil {
		utils.Fatalf("Failed to write keyfile to [%s]: %v", name, err)
	}

	fmt.Printf("new address: %x \n", key.Address)
	fmt.Println("key file: ", name)
}

func findFileByAddress(src common.Address) string {
	address := fmt.Sprintf("%x", src)
	usr, err := user.Current()
	if err != nil {
		utils.Fatalf("can not find current user: %s", err)
	}
	dir := usr.HomeDir + "/.ethereum/keystore/"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		utils.Fatalf("can not read directory: %s", err)
	}

	for _, f := range files {
		if strings.Contains(f.Name(), address) {
			return dir + f.Name()
		}
	}

	fmt.Println("key file not found, please enter file name:")
	name := terminal.PlainTextInput()
	if len(name) == 0 {
		utils.Fatalf("key file is missing")
	}
	return string(name)
	//return "/home/vlad/.ethereum/keystore/UTC--2018-05-23T12-31-42.073216971Z--2a260a110bc7b03f19c40a0bd04ff2c5dcb57594"
}

func createTransaction(args *ethapi.SendTxArgs) *types.Transaction {
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
	fmt.Println("Please enter tx for signing:")
	ts := terminal.PlainTextInput()

	var txArgs ethapi.SendTxArgs
	if err := json.Unmarshal([]byte(ts), &txArgs); err != nil {
		utils.Fatalf("tx unmarshal failed: %s", err)
	}
	if txArgs.Input == nil && txArgs.Data != nil {
		txArgs.Input = txArgs.Data
	}
	return &txArgs
}

func getPassword(secure bool) string {
	if secure {
		p := terminal.SecureInput(extended)
		return string(p)
	}
	pass, err := console.Stdin.PromptPassword("Please enter password: ")
	if err != nil {
		utils.Fatalf("Failed to read passphrase: %v", err)
	}
	return pass
}

func run(osargs []string) {
	txArgs := requestTransaction()
	tx := createTransaction(txArgs)
	keyfile := findFileByAddress(txArgs.From)
	keyjson, err := ioutil.ReadFile(keyfile)
	if err != nil {
		utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfile, err)
	}

	passphrase := getPassword(true)
	key, err := keystore.DecryptKey(keyjson, string(passphrase))
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}

	signer := types.HomesteadSigner{}
	tx, err = types.SignTx(tx, signer, key.PrivateKey)
	if err != nil {
		utils.Fatalf("Signing error: %s", err)
	}

	res, err := rlp.EncodeToBytes(tx)
	if err != nil {
		utils.Fatalf("EncodeRLP error: %s", err)
	}

	fmt.Printf("%x\n", res)
}
