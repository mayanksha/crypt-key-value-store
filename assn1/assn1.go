package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// "time"

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

var fileBlocksString string = Argon2Hash("FileBlocksString")
var metaDataString string = Argon2Hash("MetaDataString")
var userDataString string = Argon2Hash("UserDataString")
var shareDatastring string = Argon2Hash("ShareDataString")
var IVstring string = Argon2Hash("InitVector")

// The structure definition for a user record
type User struct {
	/*Username need not be encrypted with symmetric key*/
	Username      string
	SymmetricKey  []byte                     // Argon2(password), given, password has high entropy
	PrivateKey    userlib.PrivateKey         // Encrypted with the Symmetric Key
	FileKeys      map[string]FileCredentials // Indexed by filename to FileSharingKey
	MetadataIndex map[string]string          // Indexed by filename to file's metadata index
	HMAC          []byte                     // H(username + SymmetricKey + PrivateKey + FileKeys)
}
type FileSharingKey []byte

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	MetadataIndex string
	MetadataIV    []byte
	FileKey       []byte
	UUIDnonce     uuid.UUID
	RSAsignature  []byte
}

type FileCredentials struct {
	MetaDataIV []byte
	FileKey    FileSharingKey
}
type MetaData struct {
	Owner            string
	LastEditBy       string            // hash(LastEditByUserName)
	FilenameMap      map[string][]byte // Map from hash(username) to encrypted filename for that user (encrypted with symmetric key of that user)
	GenesisBlock     string            // HashValue(Owner + FilenameMap[Owner] + uuid nonce)
	GenesisUUIDNonce uuid.UUID
	LastBlock        string // HashValue(LastEditBy + FilenameMap[LastEditBy] + uuid nonce)
	LastUUIDNonce    uuid.UUID
	LastBlockIV      []byte
	HMAC             []byte // HMAC(key = FileSharingKey, Data = Owner, LastEditBy, LastEditTime, GenesisBlock, GenesisBlockNonce, LastUUIDNonce, LastBlock)
}

type Block struct {
	Owner         string
	Content       []byte
	PrevBlockHash string
	PrevBlockIV   []byte
	HMAC          []byte
}

func StoreUserDataMap(userdata *User, userDataMap *map[string][]byte) {
	bytes, _ := json.Marshal(userdata)

	iv := GetNewIV()

	cipher, _ := GetCFBEncrypt(userdata.SymmetricKey, bytes, iv)
	(*userDataMap)[Argon2Hash(userdata.Username)] = cipher
	bytes, _ = json.Marshal(userDataMap)

	userlib.DatastoreSet(userDataString, bytes)
	userlib.DatastoreSet(Argon2Hash(userdata.Username)+IVstring, iv)
}

func GetNewIV() (iv []byte) {
	iv = make([]byte, userlib.BlockSize)
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	return
}

func GetCFBEncrypt(key []byte, msg []byte, givenIV []byte) (ciphertext []byte, iv []byte) {
	ciphertext = make([]byte, len(key)+len(msg))
	iv = ciphertext[:len(key)]

	if len(givenIV) < userlib.BlockSize {
		// Load random data:w
		copy(iv, userlib.RandomBytes(len(key)))
	} else {
		copy(iv, givenIV)

	}
	/*fmt.Println(hex.EncodeToString(key))
	 *fmt.Println(hex.EncodeToString(iv))*/
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[len(key):], []byte(msg))
	return
}

func GetCFBDecrypt(key []byte, msg []byte, iv []byte) (plaintext []byte) {
	cipher := userlib.CFBDecrypter(key, iv)
	// Yes you can do this in-place
	cipher.XORKeyStream(msg[len(key):], msg[len(key):])
	plaintext = msg[len(key):]
	return
}

func PrettyPrint(i interface{}) {
	s, _ := json.MarshalIndent(i, "", "\t")
	userlib.DebugMsg(string(s))
}

// Helper function to get hex encoded Argon2 hash -- Outputs 32 bytes
func Argon2Hash(toHash string) string {
	return hex.EncodeToString(userlib.Argon2Key([]byte(toHash), nil, uint32(userlib.HashSize)))
}

// Helper function to get hex encoded Argon2 hash of password -- Outputs 64 bytes
func Argon2PasswordHash(password string) []byte {
	return userlib.Argon2Key([]byte(password), nil, uint32(userlib.BlockSize))
}

func GetUserIV(username string) (iv []byte) {
	iv, _ = userlib.DatastoreGet(Argon2Hash(username) + IVstring)
	return
}

func MetadataHMAC(metadata MetaData, SymmetricKey []byte) ([]byte, error) {
	macInit := userlib.NewHMAC(SymmetricKey)
	macInit.Write([]byte(metadata.Owner))
	bytes, err := json.Marshal(metadata.FilenameMap)
	if err != nil {
		return nil, err
	}
	macInit.Write(bytes)
	macInit.Write([]byte(metadata.GenesisBlock))
	macInit.Write([]byte(metadata.GenesisUUIDNonce.String()))
	macInit.Write([]byte(metadata.LastBlock))
	macInit.Write([]byte(metadata.LastUUIDNonce.String()))
	macInit.Write(metadata.LastBlockIV)
	return macInit.Sum(nil), nil
}

func BlockHMAC(block Block, fileKey []byte) ([]byte, error) {
	//fmt.Println("Inside BlockHMAC: prev: " + block.PrevBlockHash)
	//fmt.Println(string(block.Content))
	macInit := userlib.NewHMAC(fileKey)

	macInit.Write([]byte(block.Owner))
	macInit.Write(block.Content)
	macInit.Write([]byte(block.PrevBlockHash))
	macInit.Write(block.PrevBlockIV)
	return macInit.Sum(nil), nil
}

func UserHMAC(userdata User) ([]byte, error) {
	macInit := userlib.NewHMAC(userdata.SymmetricKey)

	macInit.Write([]byte(userdata.Username))
	var bytes []byte
	bytes, err := json.Marshal(userdata.PrivateKey)
	if err != nil {
		return nil, err
	}
	macInit.Write(bytes)
	bytes, err = json.Marshal(userdata.FileKeys)
	if err != nil {
		return nil, err
	}
	macInit.Write(bytes)
	bytes, err = json.Marshal(userdata.MetadataIndex)
	if err != nil {
		return nil, err
	}
	macInit.Write(bytes)
	return macInit.Sum(nil), nil
}

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

/*
 * This creates a user.  It will only be called once for a user
 * (unless the keystore and datastore are cleared during testing purposes)
 *
 * It should store a copy of the userdata, suitably encrypted, in the
 * datastore and should store the user's public key in the keystore.
 *
 * The datastore may corrupt or completely erase the stored
 * information, but nobody outside should be able to get at the stored
 * User data: the name used in the datastore should not be guessable
 * without also knowing the password and username.
 *
 * You are not allowed to use any global storage other than the
 * keystore and the datastore functions in the userlib library.
 *
 * You can assume the user has a STRONG password
 **/
func InitUser(username string, password string) (userdataptr *User, err error) {

	_, ok := userlib.DatastoreGet(userDataString)
	if !ok {
		newUserMap := make(map[string]User)
		bytes, err := json.Marshal(newUserMap)
		if err != nil {
			return nil, err
		}
		userlib.DatastoreSet(userDataString, bytes)
	}
	hashedPass := Argon2PasswordHash(password)
	val, ok := userlib.DatastoreGet(userDataString)

	var userDataMap map[string][]byte
	json.Unmarshal(val, &userDataMap)

	key, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	// Set the Public Key in Keystore
	pubkey := key.PublicKey
	userlib.KeystoreSet(username, pubkey)

	// Populate User struct
	var userdata User
	userdata.Username = username
	userdata.SymmetricKey = []byte(hashedPass)
	userdata.PrivateKey = *key
	userdata.FileKeys = make(map[string]FileCredentials)
	userdata.MetadataIndex = make(map[string]string)
	userdata.HMAC, err = UserHMAC(userdata)
	if err != nil {
		return nil, err
	}
	StoreUserDataMap(&userdata, &userDataMap)
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

func GetUser(username string, password string) (userdataptr *User, err error) {
	hashedPass := Argon2PasswordHash(password)
	// val contains the byte slice for the whole userDataMap
	val, ok := userlib.DatastoreGet(userDataString)
	if !ok {
		err := errors.New("[GetUser]: userDataString wasn't indexed in Datastore.")
		return nil, err
	}
	var userDataMap map[string][]byte

	json.Unmarshal(val, &userDataMap)

	//check if the user exists in map
	hashedUsername := Argon2Hash(username)
	val, ok = userDataMap[hashedUsername]
	if !ok {
		err := errors.New("[GetUser]: User not present in Datastore.")
		return nil, err
	}

	if len(val) < userlib.BlockSize {
		return nil, errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	// Below val is the actual decrypted bytes of User struct
	userDataIV := GetUserIV(username)

	val = GetCFBDecrypt(hashedPass, val, userDataIV)
	var userdata User
	json.Unmarshal(val, &userdata)

	//check if the password is correct
	authPass := []byte(Argon2PasswordHash(password))
	if userlib.Equal(userdata.SymmetricKey, authPass) != true {
		err := errors.New("[GetUser]: User's password doesn't match.")
		return nil, err
	}

	//calculate newHMAC of fetched User
	hmac, err := UserHMAC(userdata)
	if err != nil {
		return nil, err
	}
	//check if HMAC is same(not tampered)
	if userlib.Equal(hmac, userdata.HMAC) != true {
		err := errors.New("[GetUser]: User's data has been tampered.")
		return nil, err
	}
	return &userdata, nil
}

// This stores a file in the datastore.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	/*fmt.Println("[StoreFile]")*/
	if userdata == nil {
		return
	}

	// The file's MetaData is indexed into datastore by the string
	var oldMetadata MetaData
	var metadata MetaData
	var fileKey FileSharingKey

	metadataIndex := metaDataString + userdata.Username + filename + hex.EncodeToString(userdata.SymmetricKey)
	metadataIndexHashed := Argon2Hash(metadataIndex)
	val, ok := userlib.DatastoreGet(metadataIndexHashed)

	/*
	 *  For first store, just store the file.
	 *  For second store on the same file, preserve its file key so that
	 *  sharing can remain active. Also, update the new Owner of the Metadata
	 *	and update the HMAC too.
	 **/

	var metadataIV []byte
	fileKeys, ok := userdata.FileKeys[filename]
	if ok {
		metadataIV = fileKeys.MetaDataIV
	} else {
		metadataIV = nil
	}
	if ok {

		if len(val) < userlib.BlockSize {
			return
		}
		val = GetCFBDecrypt([]byte(fileKeys.FileKey), val, metadataIV)
		json.Unmarshal(val, &oldMetadata)

		// Check the HMAC
		calcMetadataHMAC, err := MetadataHMAC(oldMetadata, []byte(userdata.FileKeys[filename].FileKey))

		// If err, then completely reset that file's oldMetadata
		if err != nil {
			userlib.DatastoreSet(metadataIndexHashed, nil)
			return
		}
		if userlib.Equal(calcMetadataHMAC, oldMetadata.HMAC) != true {
			panic(errors.New("[StoreFile]: Someone tried to store a file of which he wasn't the owner."))
		}

		fileKey = fileKeys.FileKey
		// Set new Owner
		metadata.Owner = userdata.Username
		hashedUsername := Argon2Hash(userdata.Username)
		metadata.LastEditBy = hashedUsername
		metadata.FilenameMap = oldMetadata.FilenameMap

	} else {
		randUUID := uuid.New().String()
		fileKey = FileSharingKey(Argon2PasswordHash(randUUID))

		// Random UUID in string form
		// Before anything else, update the User struct with new fileKey
		/*    // Later set properly
		 *    userdata.FileKeys[filename] = FileCredentials{nil, FileSharingKey(fileKey)}
		 **/
		hashedUsername := Argon2Hash(userdata.Username)

		// Populate the file metadata
		metadata.Owner = userdata.Username
		metadata.LastEditBy = hashedUsername
		metadata.FilenameMap = make(map[string][]byte)
		metadata.FilenameMap[hashedUsername] = []byte(Argon2Hash(filename))
	}

	// For a new file, generate a new uuid
	metadata.GenesisUUIDNonce = uuid.New()
	genesisBlockNumber := 0
	blockIndex := fileBlocksString + userdata.Username + metadata.GenesisUUIDNonce.String() + string(genesisBlockNumber) + filename
	blockIndexHashed := Argon2Hash(blockIndex)
	metadata.GenesisBlock = blockIndexHashed

	metadata.LastUUIDNonce = metadata.GenesisUUIDNonce
	metadata.LastBlock = metadata.GenesisBlock

	//fmt.Println(metadata.LastBlock)

	// Update MetadataIndex inside userdata and also the HMAC too
	userdata.MetadataIndex[filename] = metadataIndexHashed

	val, ok = userlib.DatastoreGet(userDataString)
	if !ok {
		return
	}
	// Again get the userdatamap so as to update the new file key, IV and metadataIndex
	var userDataMap map[string][]byte
	json.Unmarshal(val, &userDataMap)

	// Marshal Metadata and store in Datastore

	_, ok = userlib.DatastoreGet(metadata.GenesisBlock)
	if ok {
		// Next to impossible, since two random hashes are very unlikely to collide
		errString := "[StoreFile] [Argon2Key BlockHash Collision]: " + blockIndex + " Collided"
		panic(errString)
	}

	// For the Genesis Block, PrevBlockHash must be ""
	var block Block
	block.Owner = metadata.Owner
	block.Content = data
	block.PrevBlockHash = ""
	block.PrevBlockIV = nil

	// Get the HMAC of the current block structure
	// ******************** StoreBlock
	hmac, err := BlockHMAC(block, fileKey)
	if err != nil {
		panic(err)
	}
	block.HMAC = hmac
	blockBytes, err := json.Marshal(block)
	if err != nil {
		panic(err)
	}
	cipher, blockIV := GetCFBEncrypt(fileKey, blockBytes, nil)
	userlib.DatastoreSet(metadata.GenesisBlock, cipher)
	// ********************

	// ******************** Store Metadata
	// Get the HMAC of the current metadata structure
	metadata.LastBlockIV = blockIV
	hmac, err = MetadataHMAC(metadata, fileKey)
	if err != nil {
		panic(err)
	}
	metadata.HMAC = hmac
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	if metadataIV == nil {
		cipher, metadataIV = GetCFBEncrypt(fileKey, metadataBytes, nil)
	} else {
		cipher, _ = GetCFBEncrypt(fileKey, metadataBytes, metadataIV)
	}

	userlib.DatastoreSet(metadataIndexHashed, cipher)

	val, ok = userlib.DatastoreGet(metadataIndexHashed)

	if len(val) < userlib.BlockSize {
		panic(errors.New("[GetUser]: cipher length should > aes.BlockSize"))
	}
	val = GetCFBDecrypt(fileKey, val, metadataIV)
	json.Unmarshal(val, &metadata)
	// ********************

	// ******************** Store Userdata
	userdata.FileKeys[filename] = FileCredentials{metadataIV, fileKey}
	hmac, err = UserHMAC(*userdata)
	if err != nil {
		panic(err)
	}
	userdata.HMAC = hmac
	StoreUserDataMap(userdata, &userDataMap)
	// ********************
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	if userdata == nil {
		return errors.New("[AppendFile]: nil userdata pointer")
	}
	//fmt.Println("AppendFile called: " + filename + string(data))

	// **************************************************************
	// Copied from GetUser
	val, ok := userlib.DatastoreGet(userDataString)
	if !ok {
		return errors.New("[GetUser]: userDataString wasn't indexed in Datastore.")
	}
	var userDataMap map[string][]byte
	json.Unmarshal(val, &userDataMap)

	hashedUsername := Argon2Hash(userdata.Username)
	val, ok = userDataMap[hashedUsername]
	if !ok {
		err := errors.New("[GetUser]: User not present in Datastore.")
		return err
	}
	// Below val is the actual decrypted bytes of User struct
	userDataIV := GetUserIV(userdata.Username)

	if len(val) < userlib.BlockSize {
		return errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}

	val = GetCFBDecrypt(userdata.SymmetricKey, val, userDataIV)
	var getUserAgain User
	json.Unmarshal(val, &getUserAgain)
	userdata.FileKeys = getUserAgain.FileKeys
	userdata.MetadataIndex = getUserAgain.MetadataIndex
	userdata.HMAC, _ = UserHMAC(*userdata)
	// **************************************************************

	metadataIndexHashed := userdata.MetadataIndex[filename]
	val, ok = userlib.DatastoreGet(metadataIndexHashed)
	if !ok {
		return errors.New("[AppendFile]: File not Found: " + filename)
	}
	var metadataIV []byte
	fileKeys, ok := userdata.FileKeys[filename]
	if ok {
		metadataIV = fileKeys.MetaDataIV
	} else {
		return errors.New("[AppendFile]: userdata.FileKeys[filename] returned nothing")
	}

	if len(val) < userlib.BlockSize {
		return errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	val = GetCFBDecrypt([]byte(fileKeys.FileKey), val, metadataIV)

	//Decrypt everything you encrypt
	//get file key
	fileKey := userdata.FileKeys[filename].FileKey

	var metadata MetaData
	json.Unmarshal(val, &metadata)

	//fmt.Println(metadata.LastUUIDNonce)
	//fmt.Println(metadata.LastBlock)

	//check the HMAC
	calcMetadataHMAC, err := MetadataHMAC(metadata, []byte(userdata.FileKeys[filename].FileKey))

	if userlib.Equal(calcMetadataHMAC, metadata.HMAC) != true {
		return errors.New("[AppendFile]: Something Wrong with MetaDataHMAC")
	}

	// This is useless and can be removed later when refactoring
	genesisBlockNumber := 0
	newUUIDNonce := uuid.New()
	newBlockIndex := fileBlocksString + userdata.Username + newUUIDNonce.String() + string(genesisBlockNumber) + filename
	newBlockIndexHashed := Argon2Hash(newBlockIndex)

	// Store the last block hash temporarily before it gets updated
	temporaryLastBlock := metadata.LastBlock
	temporaryLastBlockIV := metadata.LastBlockIV

	var block Block
	block.Owner = metadata.Owner
	block.Content = data
	block.PrevBlockHash = temporaryLastBlock
	block.PrevBlockIV = temporaryLastBlockIV

	// Get the HMAC of the current block structure
	hmac, err := BlockHMAC(block, []byte(fileKey))
	if err != nil {
		return err
	}
	block.HMAC = hmac
	bytes, err := json.Marshal(block)
	if err != nil {
		return err
	}
	cipher, newBlockIV := GetCFBEncrypt([]byte(fileKey), bytes, nil)
	userlib.DatastoreSet(newBlockIndexHashed, cipher)

	// ******************** Store Metadata ***********************
	// Update the LastBlock details in metadata
	metadata.LastUUIDNonce = newUUIDNonce
	metadata.LastBlock = newBlockIndexHashed
	metadata.LastEditBy = Argon2Hash(userdata.Username)
	metadata.LastBlockIV = newBlockIV

	hmac, err = MetadataHMAC(metadata, fileKey)
	if err != nil {
		panic(err)
	}
	metadata.HMAC = hmac
	// Marshal Metadata and update in Datastore
	bytes, err = json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	// Encrypt the metadata
	// Use previous metadataIV so that you don't have to update IV in User struct
	cipher, metadataIV = GetCFBEncrypt([]byte(fileKey), bytes, metadataIV)
	userlib.DatastoreSet(metadataIndexHashed, cipher)
	// ***************************************************************
	return nil
}

// This loads a file from the Datastore.
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	/*fmt.Println("[LoadFile]")*/
	if userdata == nil {
		return nil, errors.New("[LoadFile]: nil userdata pointer")
	}

	// **************************************************************
	// Copied from GetUser
	val, ok := userlib.DatastoreGet(userDataString)
	if !ok {
		err := errors.New("[GetUser]: userDataString wasn't indexed in Datastore.")
		return nil, err
	}
	var userDataMap map[string][]byte
	json.Unmarshal(val, &userDataMap)

	hashedUsername := Argon2Hash(userdata.Username)
	val, ok = userDataMap[hashedUsername]
	if !ok {
		err := errors.New("[GetUser]: User not present in Datastore.")
		return nil, err
	}
	// Below val is the actual decrypted bytes of User struct
	userDataIV := GetUserIV(userdata.Username)

	if len(val) < userlib.BlockSize {
		return nil, errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	val = GetCFBDecrypt(userdata.SymmetricKey, val, userDataIV)
	var getUserAgain User
	json.Unmarshal(val, &getUserAgain)
	userdata.FileKeys = getUserAgain.FileKeys
	userdata.MetadataIndex = getUserAgain.MetadataIndex
	userdata.HMAC, _ = UserHMAC(*userdata)
	// **************************************************************

	//fmt.Println("LoadFile called: " + filename)
	metadataIndexHashed := userdata.MetadataIndex[filename]
	val, ok = userlib.DatastoreGet(metadataIndexHashed)
	if !ok {
		return nil, errors.New("[LoadFile]: File not Found: " + filename)
	}

	// Decrypt the metadata
	var metadataIV []byte
	fileKeys, ok := userdata.FileKeys[filename]
	if ok {
		metadataIV = fileKeys.MetaDataIV
	} else {
		return nil, errors.New("[LoadFile]: userdata.FileKeys[filename] returned nothing")
	}
	fileKey := userdata.FileKeys[filename].FileKey

	if len(val) < userlib.BlockSize {
		return nil, errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	val = GetCFBDecrypt(fileKey, val, metadataIV)
	//get file key
	var metadata MetaData
	json.Unmarshal(val, &metadata)

	//check the HMAC
	calcMetadataHMAC, err := MetadataHMAC(metadata, fileKey)
	if err != nil {
		return nil, err
	}
	if userlib.Equal(calcMetadataHMAC, metadata.HMAC) != true {
		return nil, errors.New("[LoadFile]: Something Wrong with MetaDataHMAC")
	}

	// Traverses all block until LastBlock and checks their integrity

	var temp [][]byte
	prevBlockHash := metadata.LastBlock
	prevBlockIV := metadata.LastBlockIV
	for prevBlockHash != "" {
		val, ok := userlib.DatastoreGet(prevBlockHash)
		// check if block is present or not
		if !ok {
			return nil, errors.New("[LoadFile]: Failed")
		}
		var block Block

		if len(val) < userlib.BlockSize {
			return nil, errors.New("[GetUser]: cipher length should > aes.BlockSize")
		}
		val = GetCFBDecrypt([]byte(fileKey), val, prevBlockIV)
		json.Unmarshal(val, &block)

		calcBlockHMAC, err := BlockHMAC(block, []byte(fileKey))
		if err != nil {
			return nil, errors.New("[LoadFile]: Failed")
		}
		if userlib.Equal(calcBlockHMAC, block.HMAC) != true {
			return nil, errors.New("[LoadFile]: Failed HMAC unequal")
		}
		temp = append(temp, block.Content)
		prevBlockHash = block.PrevBlockHash
		prevBlockIV = block.PrevBlockIV
	}
	// Reverse iterate over temp to get data in correct order
	for i := len(temp) - 1; i >= 0; i-- {
		// Below is a variadic function
		// https://stackoverflow.com/questions/16248241/concatenate-two-slices-in-go
		data = append(data, temp[i]...)
		//fmt.Println(string(data))
	}

	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// fmt.Printf("\n[ShareFile]: \n")
	if userdata == nil {
		return
	}
	metadataIndexHashed := userdata.MetadataIndex[filename]
	_, ok := userlib.DatastoreGet(metadataIndexHashed)
	if !ok {
		return "", errors.New("[ShareFile] : " + filename + "not found")
	}

	fileKeys, ok := userdata.FileKeys[filename]
	if !ok {
		return "", errors.New("[ShareFile] : Error with getting userdata.FileKeys[" + filename + "]")
	}

	//get recipient's pub key
	Rekey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("[ShareFile] : " + recipient + "not found")
	}
	var sharemsg sharingRecord

	sharemsg.MetadataIndex = metadataIndexHashed
	sharemsg.MetadataIV = fileKeys.MetaDataIV
	// Just encrypt the filekey with public key
	sharemsg.FileKey, err = userlib.RSAEncrypt(&Rekey, []byte(userdata.FileKeys[filename].FileKey), nil)
	if err != nil {
		return "", err
	}
	// To prevent a replay attack
	sharemsg.UUIDnonce = uuid.New()

	sharingRecordSUM := sharemsg.MetadataIndex + sharemsg.UUIDnonce.String() + hex.EncodeToString([]byte(sharemsg.FileKey)) + hex.EncodeToString([]byte(sharemsg.UUIDnonce.String()))
	//take  hash  for signature
	sharingRecordHASH := Argon2Hash(sharingRecordSUM)

	sharemsg.RSAsignature, err = userlib.RSASign(&userdata.PrivateKey, []byte(sharingRecordHASH))

	randUUID := uuid.New().String()
	shareid := Argon2Hash(randUUID)

	var shareDataMap map[string][]byte
	_, ok = userlib.DatastoreGet(shareDatastring)
	if !ok {
		shareDataMap = make(map[string][]byte)
		bytes, err := json.Marshal(shareDataMap)
		if err != nil {
			return "", err
		}
		userlib.DatastoreSet(shareDatastring, bytes)
	}
	val, ok := userlib.DatastoreGet(shareDatastring)
	json.Unmarshal(val, &shareDataMap)

	_, ok = shareDataMap[shareid]
	if ok {
		return "", errors.New("[ShareFile]: Random Hash Collision")
	}

	/*PrettyPrint(sharemsg)*/
	bytes, err := json.Marshal(sharemsg)
	if err != nil {
		return "", err
	}
	shareDataMap[shareid] = bytes
	bytes, err = json.Marshal(shareDataMap)
	if err != nil {
		return "", err
	}
	userlib.DatastoreSet(shareDatastring, bytes) //store the encrypted sharemsg []byte in Datastore

	/*val, ok = userlib.DatastoreGet(shareDatastring)
	 *json.Unmarshal(val, &shareDataMap)
	 *bytes, ok = shareDataMap[msgid]
	 *json.Unmarshal(bytes, &sharemsg)
	 *PrettyPrint(sharemsg)*/
	return shareid, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	/*fmt.Printf("\n[ReceiveFile]: \n")*/

	if userdata == nil {
		return errors.New("[ReceiveFile]: nil userdata pointer")
	}
	// Get(msgid)
	// Use the private key to decrypt the sharemsg struct
	// Get the Pubkey of sender
	// Use the sender's pubkey to verify signature
	// User Filekeys update

	val, ok := userlib.DatastoreGet(shareDatastring)
	if !ok {
		return errors.New("[ReceiveFile]: shareDatastring wasn't indexed in Datastore.")
	}
	var shareDataMap map[string][]byte
	json.Unmarshal(val, &shareDataMap)

	bytes, ok := shareDataMap[msgid]
	if !ok {
		return errors.New("[ReceiveFile]: msgid note found in shareDataMap")
	}
	var sharemsg sharingRecord
	json.Unmarshal(bytes, &sharemsg)

	// Pubkey of sender  from keyStore
	Sekey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("[ReceiveFile] : Sender =  " + sender + "not found")
	}
	sharingRecordSUM := sharemsg.MetadataIndex + sharemsg.UUIDnonce.String() + hex.EncodeToString([]byte(sharemsg.FileKey)) + hex.EncodeToString([]byte(sharemsg.UUIDnonce.String()))
	sharingRecordHASH := Argon2Hash(sharingRecordSUM)

	err := userlib.RSAVerify(&Sekey, []byte(sharingRecordHASH), sharemsg.RSAsignature)

	if err != nil {
		return errors.New("[ReceiveFile]: RSA signature is Invalid")
	}
	// Decrypt the file key with Private Key of recipient
	decrypted, err := userlib.RSADecrypt(&userdata.PrivateKey, sharemsg.FileKey, nil)
	if err != nil {
		return err
	}
	// update users.filekey
	userdata.FileKeys[filename] = FileCredentials{sharemsg.MetadataIV, FileSharingKey(decrypted)}
	userdata.MetadataIndex[filename] = sharemsg.MetadataIndex
	userdata.HMAC, _ = UserHMAC(*userdata)

	val, ok = userlib.DatastoreGet(userDataString)
	if !ok {
		return errors.New("[ReceiveFile]: Errors while getting userDataString")
	}
	var userDataMap map[string][]byte

	json.Unmarshal(val, &userDataMap)

	hashedUsername := Argon2Hash(userdata.Username)
	_, ok = userDataMap[hashedUsername]
	if !ok {
		return errors.New("[ReceiveFile]: Errors while getting user from userDataMap")
	}

	StoreUserDataMap(userdata, &userDataMap)

	delete(shareDataMap, msgid)
	bytes, err = json.Marshal(shareDataMap)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(shareDatastring, bytes) //store the encrypted sharemsg []byte in Datastore
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	userlib.DebugMsg("[RevokeFile]")
	metadataIndexHashed := userdata.MetadataIndex[filename]
	val, ok := userlib.DatastoreGet(metadataIndexHashed)
	if !ok {
		return errors.New("[RevokeFile]: error while accessing metadata")
	}

	fileKeys, ok := userdata.FileKeys[filename]
	if !ok {
		return errors.New("")
	}
	oldFilekey := fileKeys.FileKey
	metadataIV := fileKeys.MetaDataIV

	if len(val) < userlib.BlockSize {
		return errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	val = GetCFBDecrypt(oldFilekey, val, metadataIV)

	var metadata MetaData
	json.Unmarshal(val, &metadata)

	if userdata.Username != metadata.Owner {
		return errors.New("[RevokeFile]: Sorry, you're not the owner and hence not allowed to Revoke")
	}
	/*
	 *   Use the old File Key to decrypt the metadata, then decrypt all the blocks
	 *   and reencrypt all blocks with newFileKey
	 * 	 oldFileKey := userdata.FileKeys[filename]
	 **/

	// Generate a new FileKey
	randUUID := uuid.New().String()
	newFilekey := FileSharingKey(Argon2PasswordHash(randUUID))

	prevBlockHash := metadata.LastBlock
	prevBlockIV := metadata.LastBlockIV
	for prevBlockHash != "" {
		val, ok := userlib.DatastoreGet(prevBlockHash)
		// check if block is present or not
		if !ok {
			return errors.New("[RevokeFile]: Failed")
		}
		var block Block

		if len(val) < userlib.BlockSize {
			return errors.New("[GetUser]: cipher length should > aes.BlockSize")
		}
		val = GetCFBDecrypt([]byte(oldFilekey), val, prevBlockIV)
		json.Unmarshal(val, &block)

		calcBlockHMAC, err := BlockHMAC(block, oldFilekey)
		if err != nil {
			return errors.New("[RevokeFile]: Failed")
		}
		if userlib.Equal(calcBlockHMAC, block.HMAC) != true {
			return errors.New("[RevokeFile]: Failed HMAC unequal")
		}
		// Update the HMAC of block with newFileKey
		block.HMAC, _ = BlockHMAC(block, newFilekey)
		// Now re-encrypt the block with newfilekey
		blockBytes, err := json.Marshal(block)
		if err != nil {
			return err
		}
		cipher, _ := GetCFBEncrypt(newFilekey, blockBytes, prevBlockIV)
		userlib.DatastoreSet(prevBlockHash, cipher)

		prevBlockHash = block.PrevBlockHash
		prevBlockIV = block.PrevBlockIV
	}

	// ************************************
	// Now re-encrypt the metadata with newfilekey
	hmac, _ := MetadataHMAC(metadata, newFilekey)
	metadata.HMAC = hmac
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	cipher, _ := GetCFBEncrypt(newFilekey, metadataBytes, metadataIV)
	userlib.DatastoreSet(metadataIndexHashed, cipher)

	val, ok = userlib.DatastoreGet(metadataIndexHashed)

	if len(val) < userlib.BlockSize {
		return errors.New("[GetUser]: cipher length should > aes.BlockSize")
	}
	val = GetCFBDecrypt(newFilekey, val, metadataIV)
	json.Unmarshal(val, &metadata)

	// ************************************

	val, _ = userlib.DatastoreGet(userDataString)
	var userDataMap map[string][]byte
	json.Unmarshal(val, &userDataMap)

	userdata.FileKeys[filename] = FileCredentials{metadataIV, newFilekey}
	hmac, err = UserHMAC(*userdata)
	if err != nil {
		return err
	}
	userdata.HMAC = hmac

	StoreUserDataMap(userdata, &userDataMap)
	/*val, ok = userDataMap[hashedUsername]
	 *if !ok {
	 *  err := errors.New("[GetUser]: User not present in Datastore.")
	 *  return err
	 *}
	 * Below val is the actual decrypted bytes of User struct
	 *val = GetCFBDecrypt(userdata.SymmetricKey, val, serDataIV)
	 *var foobar User
	 *json.Unmarshal(val, &foobar)
	 *PrettyPrint(foobar)*/
	return nil
}
