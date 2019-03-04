package assn1

import "github.com/fenilfadadu/CS628-assn1/userlib"
import "testing"
import "reflect"
import (
	"crypto/sha256"
	"encoding/hex"
)

/*func TestCFB(t *testing.T) {
*  key := []byte("example key 1234")
*  msg := "This is a Test"
*  ciphertext, iv := GetCFBEncrypt(key, []byte(msg), nil)
*
*  plaintext := GetCFBDecrypt(key, ciphertext, iv)
*  if msg != string(plaintext) {
	*    t.Error("Decryption Failed")
	*  }
	*}*/

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Logf("%x \n", sha256.Sum256([]byte("app")))
	temp := hex.EncodeToString(userlib.Argon2Key([]byte("app"), nil, 32))
	t.Logf("%v \n", temp)
	t.Logf("%x \n", userlib.Argon2Key([]byte("app"), nil, 32))
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()

	userlib.DebugPrint = false
	aliceUser := "alice"
	alicePass := "foobar"
	u, err := InitUser(aliceUser, alicePass)
	if err != nil {
		t.Error("Got InitUser Error", err)
	} else {
		t.Logf("Username =  %s\n", u.Username)
		t.Logf("HMAC = %x", u.HMAC)
	}
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}

	// t.Log() only produces output if you run with "go test -v"
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	username := "alice"
	password := "fubar"
	t.Logf("username = %v, password = %v\n", username, password)
	u, err := GetUser(username, password)
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	password = "foobar"
	t.Logf("username = %v, password = %v\n", username, password)
	u, err = GetUser(username, password)
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	t.Logf("Loaded user: username = %v\nHMAC = %x\n", u.Username, u.HMAC)
	/*t.Log(prettyPrint(*u))*/

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	/*t.Log(prettyPrint(*u))*/

	v2, err2 := u.LoadFile("file1")

	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
	v3 := []byte("<3 November Rain!")

	/*err = u.AppendFile("file2", v3)
	*if err != nil {
		*  t.Error(err)
		*}*/
	err = u.AppendFile("file1", v3)
	if err != nil {
		t.Error(err)
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(v2))

	v3 = []byte("Oh, this is a new FILE!!!!")
	u.StoreFile("file1", v3)

	/*t.Log(prettyPrint(*u))*/
	v3, err = u.LoadFile("file1")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(v3))

	err = u.AppendFile("file1", v2)
	if err != nil {
		t.Error(err)
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(v2))
}

func TestShare(t *testing.T) {
	file1 := "file1"
	alice, err := GetUser("alice", "foobar")
	/*t.Log(prettyPrint(*alice))*/
	if err != nil {
		t.Error("Failed to load user", err)
	}
	v3 := []byte("[1] New File!")
	alice.StoreFile(file1, v3)
	bob, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	v, err = alice.LoadFile(file1)
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", alice.Username, file1, v)
	}

	var msgid string
	msgid, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	err = bob.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Logf("User %s, filename %s, data = %s\n", bob.Username, "file2", v)

	v2, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

	// bob shares the file with a 3rd user Charlie
	charlie, err2 := InitUser("charlie", "shoobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}
	msgid, err = bob.ShareFile("file2", "charlie")
	t.Log(msgid)
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	err = charlie.ReceiveFile("file2", "bob", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	v, err = charlie.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", charlie.Username, "file2", v)
	}

	// Let Charlie append something
	charlie.AppendFile("file2", []byte("This is new Text added by Charlie"))
	// View Charlie's changes
	v, err = charlie.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from charlie", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", charlie.Username, "file2", v)
	}

	// View Alice's changes
	v, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", alice.Username, "file1", v)
	}

	v, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", bob.Username, "file1", v)
	}

	/*PrettyPrint(alice)
	*PrettyPrint(bob)
	*PrettyPrint(charlie)*/

	err = charlie.RevokeFile("file2")
	if err != nil {
		t.Error(err)
	}

	err = bob.RevokeFile("file2")
	if err != nil {
		t.Error(err)
	}
	err = alice.RevokeFile("file1")
	if err != nil {
		t.Error(err)
	}

	v, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", bob.Username, "file1", v)
	}

	// View Alice's changes
	v, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	} else {
		t.Logf("User %s, filename %s, data = %s\n", alice.Username, "file1", v)
	}
}
func TestMultiUser(t *testing.T) {
	userlib.DebugPrint = true
	user1, err := GetUser("alice", "foobar")
	if err != nil {
		t.Error("Failed to get user")
	}
	user1again, err := GetUser("alice", "foobar")
	if err != nil {
		t.Error("Failed to get user")
	}
	t1 := []byte("This is life")
	user1.StoreFile("file", t1)
	/*  m, err := user1again.LoadFile("file")
	 *  if err != nil {
	 *    t.Error(err)
	 *  }
	 *
	 *  t.Log("Contents:", string(m))*/
	t2 := []byte("fthis")
	user1again.AppendFile("file", t2)
	m, _ := user1.LoadFile("file")
	t.Log("Contents:", string(m))

}

func TestMutate(t *testing.T) {
}
