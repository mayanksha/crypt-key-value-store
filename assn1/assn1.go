package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	/*"fmt"*/
	"hash"
	"time"
	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
/*type File struct {
*  []byte content
*  []byte hmac
*}*/
type User struct {
	/*Username need not be encrypted with symmetric key*/
	Username     string
	SymmetricKey []byte                    // Argon2(password), given, password has high entropy
	PrivateKey   userlib.PrivateKey        // Encrypted with the Symmetric Key
	FileKeys     map[string]FileSharingKey // Indexed by hash(filename), FileSharingKey maps to the Current Sharing Key of the File
	HMAC         []byte                    // H(username + SymmetricKey + PrivateKey + FileKeys)
}
type FileSharingKey string // HashValue of (Owner.SymmetricKey + uuid as salt)
/*type Data struct {
 *  UserData     map[string]User
 *  FileBlocks   map[string]Block
 *  FileMetadata map[string]MetaData
 *}*/
type MetaData struct {
	Owner            string
	LastEditBy       string            // hash(LastEditByUserName)
	LastEditTime     time.Time         // hash(LastEditByUserName)
	FilenameMap      map[string]string // Map from hash(username) to encrypted filename for that user (encrypted with symmetric key of that user)
	GenesisBlock     string            // HashValue(Owner + FilenameMap[Owner] + uuid nonce)
	GenesisUUIDNonce string
	LastUUIDNonce    string
	LastBlock        string    // HashValue(LastEditBy + FilenameMap[LastEditBy] + uuid nonce)
	HMAC             hash.Hash // HMAC(key = FileSharingKey, Data = Owner, LastEditBy, LastEditTime, GenesisBlock, GenesisBlockNonce, LastUUIDNonce, LastBlock)
}

type Block struct {
	Owner         string
	Content       []byte
	PrevBlockHash string
	HMAC          hash.Hash
}
type temporaryBlock struct {
	Owner         string
	Content       []byte
	PrevBlockHash string
	HMAC          []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	UserDataString := hex.EncodeToString(userlib.Argon2Key([]byte("UserDataString"), nil, uint32(userlib.HashSize)))
	_, ok := userlib.DatastoreGet(UserDataString)
	if !ok {
		newUserMap := make(map[string]User)
		bytes, err := json.Marshal(newUserMap)
		if err != nil {
			return nil, err
		}
		userlib.DatastoreSet(UserDataString, bytes)
	}
	val, ok := userlib.DatastoreGet(UserDataString)
	var userDataMap map[string]User
	json.Unmarshal(val, &userDataMap)

	hashedUsername := hex.EncodeToString(userlib.Argon2Key([]byte(username), nil, uint32(userlib.HashSize)))

	key, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	// Set the Public Key in Keystore
	pubkey := key.PublicKey
	userlib.KeystoreSet(username, pubkey)

	// Populate User struct
	userdata.Username = username
	userdata.SymmetricKey = userlib.Argon2Key([]byte(password), nil, 2*uint32(userlib.HashSize))
	userdata.PrivateKey = *key
	userdata.FileKeys = make(map[string]FileSharingKey)

	macInit := userlib.NewHMAC(userdata.SymmetricKey)

	macInit.Write([]byte(userdata.Username))
	var bytes []byte
	bytes, err = json.Marshal(userdata.PrivateKey)
	if err != nil {
		return nil, err
	}
	macInit.Write(bytes)
	bytes, err = json.Marshal(userdata.FileKeys)
	if err != nil {
		return nil, err
	}
	userdata.HMAC = macInit.Sum(nil)

	// To-do CFB encryption using Symmetric Key
	userDataMap[hashedUsername] = userdata
	bytes, err = json.Marshal(userDataMap)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(UserDataString, bytes)
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	return
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	var block Block
	var metadata MetaData
	var temp temporaryBlock
	_, ok := userlib.DatastoreGet("FileBlocks")
	if !ok {
		initData := make(map[string]Block)
		bytes, err := json.Marshal(initData)
		if err != nil {

		}
		userlib.DatastoreSet("FileBlocks", bytes)
	}

	metadata.Owner = userdata.Username
	// Block Details for Data
	block.Content = data
	block.Owner = userdata.Username
	block.PrevBlockHash = ""

	temp.Content = data
	temp.Owner = userdata.Username
	temp.PrevBlockHash = ""

	bytes, err := json.Marshal(temp)
	if err != nil {

	}
	block.HMAC = userlib.NewHMAC(bytes)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
