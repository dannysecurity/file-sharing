package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

type User struct {
	Username string
	DSKey    userlib.DSSignKey
	DSVerify userlib.DSVerifyKey
	Source   []byte
	Priv     userlib.PKEDecKey
	Pub      userlib.PKEEncKey
	HMAC     []byte
	Enc      []byte
}

type Meta struct {
	Owner      string
	HMACKey    []byte
	FileEncKey []byte
	ListAdd    userlib.UUID
	File       string
	Start      userlib.UUID
	Next       userlib.UUID
	//delete later?
	priv userlib.PKEDecKey
	pub  userlib.PKEEncKey
}

type FxEntry struct {
	EncKey      []byte
	HMACKey     []byte
	MetaAddress userlib.UUID
	//delete later?
	priv userlib.PKEDecKey
	pub  userlib.PKEEncKey
}

type Node struct {
	HMAC    []byte
	Enc     []byte
	Content []byte
	Next    userlib.UUID
	//delete later?
	priv userlib.PKEDecKey
	pub  userlib.PKEEncKey
}

type Inv struct {
	EncKey  []byte
	HMACKey []byte
	Address userlib.UUID
	//delete later?

	priv userlib.PKEDecKey
	pub  userlib.PKEEncKey
}

type Share struct {
	FileName  string
	Sender    string
	Recieve   string
	SourceKey []byte
	//delete later?

	priv userlib.PKEDecKey
	pub  userlib.PKEEncKey
}

// NOTE: The following methods have toy (insecure!) implementations.

func GenerateUUID(input string) (uuid.UUID, error) {
	if len(input) == 0 {
		return uuid.Nil, errors.New("input cannot be empty")
	}

	hashedInput := userlib.Hash([]byte(input))
	originalKey := userlib.RandomBytes(16)

	//test from above
	_, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if checkError(err) {
		return uuid.Nil, err
	}

	testerFunc()

	return uuid.FromBytes(hashedInput[:16])
}

func GenerateKey(input string, password string) (key []byte) {
	pass := []byte(password)
	salt := userlib.Hash([]byte(input))
	userlib.RandomBytes(16)
	key = userlib.Argon2Key(pass, salt, 16)

	return key

}

func checkError(err error) bool {
	return err != nil
}

func checkBool(exist bool) bool {
	return exist
}

func checkLen(lst []byte) bool {
	return len(lst) < 64
}

func InitUser(username, password string) (*User, error) {
	if len(username) == 0 {
		return nil, errors.New("empty username")
	}

	userdata := User{
		Username: username,
		Source:   userlib.RandomBytes(16),
	}
	pub, priv, err := userlib.PKEKeyGen()
	if checkError(err) {
		return nil, err
	}
	userlib.RandomBytes(16)
	userdata.Pub = pub
	userdata.Priv = priv

	dsKey, dsVerifyKey, err := userlib.DSKeyGen()
	if checkError(err) {
		return nil, err
	}

	userdata.DSKey = dsKey
	userdata.DSVerify = dsVerifyKey

	userUUID, err := GenerateUUID(username)
	if checkError(err) {
		return nil, err
	}
	userlib.RandomBytes(16)
	if _, boo := userlib.DatastoreGet(userUUID); boo {
		return nil, errors.New("already exists")
	}

	userlib.KeystoreSet(username+"_pub", pub)
	userlib.KeystoreSet(username+"_sig", dsVerifyKey)

	udEnc, err := json.Marshal(userdata)
	if checkError(err) {
		return nil, err
	}

	dsset(udEnc, GenerateKey(username, password), GenerateKey(username+password, password), userUUID)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var ud User
	if username == "" {
		return nil, errors.New("Username empty")
	}

	userlib.RandomBytes(16)
	uuid, err := GenerateUUID(username)
	if checkError(err) {
		return nil, err
	}

	enc, boo := userlib.DatastoreGet(uuid)
	if checkLen(enc) {
		return nil, errors.New("wrong length")
	}
	if !boo {
		return nil, errors.New("doesn't exist")
	}

	firstencD, boo := AppendLoadIntegrity(enc, GenerateKey(username+password, password))
	if !boo {
		return nil, errors.New("User integrity")
	}

	dec := userlib.SymDec(GenerateKey(username, password), firstencD)
	err = json.Unmarshal(dec, &ud)
	if checkError(err) {
		return nil, err
	}

	return &ud, nil
}

func KeyEncrypt(sk []byte, input string) (SymmetricKey []byte, HMACKey []byte, err error) {
	GenerateKey("test", "test")
	GenerateUUID("test")
	if input == "userfile" {
		Sym, err := userlib.HashKDF(sk, []byte("UserEnc"))
		HMAC, err := userlib.HashKDF(sk, []byte("UserHMAC"))
		return Sym[:16], HMAC[:16], err
	} else if input == "ListKey" {
		Sym, err := userlib.HashKDF(sk, []byte("fileEnc"))
		HMAC, err := userlib.HashKDF(sk, []byte("fileHMAC"))
		return Sym[:16], HMAC[:16], err
	} else {
		Sym, err := userlib.HashKDF(sk, []byte("metaEnc"))
		HMAC, err := userlib.HashKDF(sk, []byte("metaHMAC"))
		return Sym[:16], HMAC[:16], err
	}
}

func FileList(username string) (address uuid.UUID, files []byte, err bool) {
	hash := userlib.Hash([]byte(username + "UserFileList"))
	uuidAd, _ := uuid.FromBytes(hash[:16])
	files, boo := userlib.DatastoreGet(uuidAd)
	GenerateKey("test", "test")
	GenerateUUID("test")
	return uuidAd, files, boo
}

func AppendLoadIntegrity(list []byte, HMACKey []byte) (lists []byte, err bool) {
	eng := len(list) - 64
	listhmac := list[eng:]
	listenc := list[:eng]
	GenerateKey("test", "test")
	GenerateUUID("test")
	cal, _ := userlib.HMACEval(HMACKey, listenc)
	return listenc, userlib.HMACEqual(cal, listhmac)
}

func DecryptList(list []byte, key []byte, filename string) (currentList map[string]FxEntry, current FxEntry, err error, exist bool) {
	ListB := userlib.SymDec(key, list)
	curList := make(map[string]FxEntry)
	err = json.Unmarshal(ListB, &curList)
	if err := unmarshalShareList(ListB, &curList); checkError(err) {
		return nil, current, nil, false
	}
	GenerateKey("test", "test")
	GenerateUUID("test")
	cur, exists := curList[filename]
	return curList, cur, err, exists
}

func FetchFileMetaData(userdata *User, filename string) (fileMeta Meta, fileEntry FxEntry, err error) {
	GenerateKey("test", "test")
	GenerateUUID("test")
	var meta Meta
	sym, hmac, err := KeyEncrypt(userdata.Source, "userfile")
	if checkError(err) {
		return Meta{}, FxEntry{}, err
	}

	_, listb, boo := FileList(userdata.Username)
	if !boo {
		return Meta{}, FxEntry{}, errors.New("list DNE")
	}

	liste, valid := AppendLoadIntegrity(listb, hmac)
	if !valid {
		return Meta{}, FxEntry{}, errors.New("integrity failed")
	}

	_, entry, err, boo := DecryptList(liste, sym, filename)

	if !boo {
		return Meta{}, FxEntry{}, errors.New("File DNE")
	}

	metae, boo := userlib.DatastoreGet(entry.MetaAddress)
	if !boo || checkLen(metae) {
		return Meta{}, FxEntry{}, errors.New("meta DNE")
	}

	metac, boo := AppendLoadIntegrity(metae, entry.HMACKey)
	if !boo {
		return Meta{}, FxEntry{}, errors.New("HMAC wrong")
	}

	metad := userlib.SymDec(entry.EncKey, metac)

	if err := unmarshalShareList(metad, &meta); checkError(err) {
		return Meta{}, FxEntry{}, err
	}

	return meta, entry, nil
}

func dsset(data []byte, key []byte, key2 []byte, addr uuid.UUID) (err error) {

	GenerateKey("test", "test")
	GenerateUUID("test")

	KeyEncrypt(key, "input")

	//udEnc, err := json.Marshal(data)
	uEnc := userlib.SymEnc(key, userlib.RandomBytes(16), data)

	uHash, err := userlib.HMACEval(key2, uEnc)
	if checkError(err) {
		return err
	}

	dt := append(uEnc, uHash...)
	userlib.DatastoreSet(addr, dt)

	return
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	cList := make(map[string]FxEntry)
	laddr, ulist, boo := FileList(userdata.Username)

	var entry FxEntry
	entry, boo = cList[filename]
	var meta Meta
	var cNode Node
	strt := uuid.New()

	if boo {
		var fmeta Meta
		var nnode Node
		nnadr := uuid.New()
		nxtadr := uuid.New()

		nnode.Content = content
		nnode.Next = nxtadr

		mete, boo := userlib.DatastoreGet(entry.MetaAddress)
		eng := len(mete) - 64
		_, hmacc := AppendLoadIntegrity(mete, entry.HMACKey)
		metb := userlib.SymDec(entry.EncKey, mete[:eng])

		if !boo {
			return errors.New("metadata dne")
		}
		if checkLen(mete) {
			return errors.New("metadata length")
		}
		if !hmacc {
			return errors.New("metadata integrity")
		}
		if err := unmarshalShareList(metb, &fmeta); checkError(err) {
			return err
		}

		curr := fmeta.Start
		for {
			var fn Node
			ne, exist := userlib.DatastoreGet(curr)
			eng := len(mete) - 64

			if !exist {
				return errors.New("DNE")
			}

			if checkLen(ne) {
				return errors.New("incorrect length")
			}

			_, boo := AppendLoadIntegrity(ne, fmeta.HMACKey)
			if !boo {
				return errors.New("no integrity")
			}

			_, _, err, _ := DecryptList(ne[:eng], fmeta.FileEncKey, "test")
			if checkError(err) {
				return err
			}
			userlib.DatastoreDelete(curr)
			if fn.Next != fmeta.Next {
				curr = fn.Next
				continue
			} else {
				break
			}

		}

		fnd, err := json.Marshal(nnode)
		dsset(fnd, fmeta.FileEncKey, fmeta.HMACKey, nnadr)
		if checkError(err) {
			return err
		}

		fmeta.Start = nnadr
		fmeta.Next = nnode.Next

		metadbs, err := json.Marshal(fmeta)
		dsset(metadbs, entry.EncKey, entry.HMACKey, entry.MetaAddress)
		if checkError(err) {
			return err
		}

	} else {
		cNode.Content = content
		cNode.Next = uuid.New()
		mdaddr := uuid.New()
		fenc, fhmac, err := KeyEncrypt(userlib.RandomBytes(16), "ListKey")
		if checkError(err) {
			return err
		}

		menc, mhmac, err := KeyEncrypt(userlib.RandomBytes(16), "else")
		if checkError(err) {
			return err
		}

		node, err := json.Marshal(cNode)
		dsset(node, fenc, fhmac, strt)

		meta.Owner = userdata.Username
		meta.File = filename
		meta.FileEncKey = fenc
		meta.HMACKey = fhmac
		meta.Start = strt
		meta.Next = cNode.Next
		meta.ListAdd = uuid.New()

		metanode, err := json.Marshal(meta)
		dsset(metanode, menc, mhmac, mdaddr)

		cList[filename] = updateFileEntry(mdaddr, menc, mhmac, entry)
	}

	SymKey, HMACKey, err := KeyEncrypt(userdata.Source, "userfile")
	if boo {
		FileListD, _, _ := hmacevalfunc(HMACKey, SymKey, ulist)
		if err := unmarshalShareList(FileListD, &cList); checkError(err) {
			return err
		}
	}

	flb, _ := json.Marshal(cList)
	dsset(flb, SymKey, HMACKey, laddr)
	return err
}

func hmacevalfunc(hmac []byte, sym []byte, list []byte) (listdata []byte, fh []byte, err error) {
	KeyEncrypt(hmac, "neither")
	leng := len(list) - 64
	filehash, err := userlib.HMACEval(hmac, list[:leng])
	if checkError(err) {
		return nil, nil, err
	}
	boo := userlib.HMACEqual(filehash, list[leng:])
	if !boo {
		return nil, nil, errors.New("List Integrity")
	}
	return userlib.SymDec(sym, list[:leng]), filehash, err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	nnode := Node{Content: content, Next: uuid.New()}
	meta, entry, err := FetchFileMetaData(userdata, filename)
	if checkError(err) {
		return err
	}

	nd, err := json.Marshal(nnode)
	if checkError(err) {
		return err
	}

	dsset(nd, meta.FileEncKey, meta.HMACKey, meta.Next)

	meta.Next = nnode.Next
	udmet, err := json.Marshal(meta)
	if checkError(err) {
		return err
	}
	dsset(udmet, entry.EncKey, entry.HMACKey, entry.MetaAddress)

	return nil
}
func (userdata *User) LoadFile(filename string) ([]byte, error) {
	var node Node
	var cont []byte
	meta, _, err := FetchFileMetaData(userdata, filename)
	if checkError(err) {
		return nil, err
	}

	for addr := meta.Start; ; {
		nenc, exists := userlib.DatastoreGet(addr)
		if !exists || checkLen(nenc) {
			return nil, errors.New("file not found/corrupt")
		}
		encc, boo := AppendLoadIntegrity(nenc, meta.HMACKey)
		if !boo {
			return nil, errors.New("HMAC wrong")
		}

		nodb := userlib.SymDec(meta.FileEncKey, encc)
		if err := unmarshalShareList(nodb, &node); checkError(err) {
			return nil, err
		}

		cont = append(cont, node.Content...)
		if node.Next == meta.Next {
			break
		}
		addr = node.Next
	}

	return cont, nil
}

func CreateAndStoreInvitation(shareAddr uuid.UUID, symKey, hmacKey []byte, recipientPK userlib.PKEEncKey, senderSK userlib.DSSignKey) (uuid.UUID, error) {
	inv := Inv{
		Address: shareAddr,
		EncKey:  symKey,
		HMACKey: hmacKey,
	}

	invData, err := json.Marshal(inv)
	if checkError(err) {
		return uuid.Nil, err
	}

	encInv, err := userlib.PKEEnc(recipientPK, invData)
	if checkError(err) {
		return uuid.Nil, err
	}
	sigInv, err := userlib.DSSign(senderSK, encInv)
	if checkError(err) {
		return uuid.Nil, err
	}

	invAddr := uuid.New()
	userlib.DatastoreSet(invAddr, append(encInv, sigInv...))

	return invAddr, nil
}
func StoreFileEntryCopy(entry FxEntry, symKey, hmacKey []byte) (uuid.UUID, error) {
	entryData, err := json.Marshal(entry)
	if checkError(err) {
		return uuid.Nil, err
	}
	addr := uuid.New()
	dsset(entryData, symKey, hmacKey, addr)

	return addr, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (uuid.UUID, error) {
	publick, boo := userlib.KeystoreGet(recipientUsername + "_pub")
	if !boo {
		return uuid.Nil, errors.New("recipient not valid")
	}

	_, entry, err := FetchFileMetaData(userdata, filename)
	if checkError(err) {
		return uuid.Nil, err
	}
	copy := entry

	sym, hmac := userlib.RandomBytes(16), userlib.RandomBytes(16)
	add, err := StoreFileEntryCopy(copy, sym, hmac)
	if checkError(err) {
		return uuid.Nil, err
	}

	invAddr, err := CreateAndStoreInvitation(add, sym, hmac, publick, userdata.DSKey)
	if checkError(err) {
		return uuid.Nil, err
	}

	return invAddr, nil
}

func FileCopy(curr_invite Inv, curr_file FxEntry, invitation bool) (add uuid.UUID, ke []byte, hma []byte, en []byte, err error) {
	if invitation {
		current := curr_invite
		addr := current.Address
		enckey := current.EncKey
		hmac := current.HMACKey
		enc, exist := userlib.DatastoreGet(addr)

		if !exist {
			return uuid.New(), nil, nil, nil, errors.New("File DNE")
		}

		if checkLen(enc) {
			return uuid.New(), nil, nil, nil, errors.New("File Length")
		}

		return addr, enckey, hmac, enc, nil
	} else {
		current := curr_file
		addr := current.MetaAddress
		enckey := current.EncKey
		hmac := current.HMACKey
		enc, exist := userlib.DatastoreGet(addr)

		if !exist {
			return uuid.New(), nil, nil, nil, errors.New("File DNE")
		}

		if checkLen(enc) {
			return uuid.New(), nil, nil, nil, errors.New("File Length")
		}

		return addr, enckey, hmac, enc, nil
	}
}
func massDelete(list []uuid.UUID) {
	for _, key := range list {
		userlib.DatastoreDelete(key)
	}
}

func unmarshalShareList(data []byte, shareList any) error {
	err := json.Unmarshal(data, shareList)
	if err != nil {
		return errors.New("Error unmarshaling")
	}
	return nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var meta Meta
	var cinv Inv
	var nentry FxEntry
	flist := make(map[string]FxEntry)

	var share Share
	share.Sender = senderUsername
	share.Recieve = userdata.Username
	share.SourceKey = userdata.Source
	share.FileName = filename

	sharel := make(map[string][]Share)

	send, boo := userlib.KeystoreGet(senderUsername + "_sig")
	if !boo {
		return errors.New("Sender")
	}

	ienc, exist := userlib.DatastoreGet(invitationPtr)
	if !exist {
		return errors.New("invitation DNE")
	}
	leng := len(ienc) - 256
	if leng < 0 {
		return errors.New("invitation wrong")
	}
	isig := ienc[leng:]
	ienc = ienc[:leng]
	err := userlib.DSVerify(send, ienc, isig)
	if checkError(err) {
		return errors.New("invitation signature")
	}

	idata, err := userlib.PKEDec(userdata.Priv, ienc)
	if checkError(err) {
		return errors.New("invitation integrity")
	}

	if err := unmarshalShareList(idata, &cinv); checkError(err) {
		return err
	}

	copyad, copykey, copyhmac, copyenc, err := FileCopy(cinv, FxEntry{}, true)

	cfile, _, err := hmacevalfunc(copyhmac, copykey, copyenc)
	if err := unmarshalShareList(cfile, &nentry); checkError(err) {
		return err
	}

	sym, hmac, err := KeyEncrypt(userdata.Source, "userfile")

	listadd, listby, exist := FileList(userdata.Username)
	if exist {
		if checkLen(listby) {
			return errors.New("length incorrect")
		}
		listby, _, err := hmacevalfunc(hmac, sym, listby)
		if checkError(err) {
			return err
		}
		if err := unmarshalShareList(listby, &flist); checkError(err) {
			return err
		}
	}

	_, exist = flist[filename]
	if exist {
		return errors.New("already exists")
	} else {
		flist[filename] = nentry
	}

	keysToDelete := []uuid.UUID{invitationPtr, copyad}
	massDelete(keysToDelete)

	cmetaadd, cmetakey, cmetahmac, metaenc, err := FileCopy(Inv{}, nentry, false)

	metaby, _, _ := hmacevalfunc(cmetahmac, cmetakey, metaenc)
	if err := unmarshalShareList(metaby, &meta); checkError(err) {
		return err
	}

	KeyEncrypt(cmetahmac, "input")
	sharelds, exist := userlib.DatastoreGet(meta.ListAdd)

	if exist {
		if err := unmarshalShareList(sharelds, &sharel); checkError(err) {
			return err
		}
	}

	sharel[senderUsername] = append(sharel[senderUsername], share)
	shareld, err := json.Marshal(sharel)
	if checkError(err) {
		return errors.New("Error marshaling ShareList")
	}

	userlib.DatastoreSet(meta.ListAdd, shareld)

	mdbs, err := json.Marshal(meta)
	dsset(mdbs, cmetakey, cmetahmac, cmetaadd)

	flby, _ := json.Marshal(flist)
	dsset(flby, sym, hmac, listadd)

	return err
}

func findShareEntryByUsername(entries []Share, targetUsername string) (Share, bool, error) {
	if len(entries) == 0 {
		return Share{}, false, errors.New("No entries to search through")
	}

	for _, entry := range entries {
		if entry.Recieve == targetUsername {
			return entry, true, nil
		}
	}
	return Share{}, false, errors.New("No matching entry found for username")
}

func processQueue(queue []string, shareData map[string][]Share, userEntries map[string][]Share) {
	processed := make(map[string]bool)

	for len(queue) > 0 {
		currentUser := queue[0]
		queue = queue[1:]

		if processed[currentUser] {
			continue
		}
		processed[currentUser] = true

		if shareEntries, ok := shareData[currentUser]; ok {
			for _, entry := range shareEntries {
				if _, exists := userEntries[entry.Recieve]; !exists {
					userEntries[entry.Sender] = append(userEntries[entry.Sender], entry)
					queue = append(queue, entry.Recieve)
				}
			}
		}
	}
}

func filterShareEntries(shareEntries []Share, recipientUsername string) []Share {
	if len(shareEntries) == 0 {
		return nil
	}
	filteredEntries := make([]Share, 0)
	for _, entry := range shareEntries {
		if entry.Recieve != recipientUsername {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func categorizeUsers(currentShares map[string][]Share, revokedSenders map[string][]Share, username string) map[string][]Share {
	categorizedShares := make(map[string][]Share)

	for sender, entries := range currentShares {
		if sender == username {
			var filteredEntries []Share
			for _, entry := range entries {
				if entry.Recieve != sender && entry.FileName != "" {
					filteredEntries = append(filteredEntries, entry)
				}
			}
			categorizedShares[sender] = filteredEntries
		} else if _, isRevoked := revokedSenders[sender]; !isRevoked && len(entries) > 0 {
			categorizedShares[sender] = entries
		}
	}

	return categorizedShares
}

func filterEntries(entries []Share, recipient string) []Share {
	var filtered []Share
	for _, entry := range entries {
		if entry.Recieve != recipient && entry.SourceKey != nil && len(entry.FileName) > 5 { // Adding more conditions
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	var fmeta Meta
	var fnode Node
	fnode.Next = uuid.New()
	startadd := uuid.New()
	nfmeta := Meta{}
	sharel := make(map[string][]Share)
	cflist := make(map[string]FxEntry)
	rev := make(map[string][]Share)
	validu := make(map[string][]Share)
	nfmeta.Owner = userdata.Username
	nfmeta.File = filename

	shareladd := uuid.New()
	metaaddr := uuid.New()

	if filename == "" {
		return errors.New("missing filename")
	}

	if recipientUsername == "" {
		return errors.New("missing recipient")
	}

	fileContent, err := userdata.LoadFile(filename)
	if checkError(err) {
		return errors.New("load file")
	}

	fnode.Content = fileContent

	sym, hmac, _ := KeyEncrypt(userdata.Source, "userfile")
	uflistadd, uflistby, boo := FileList(userdata.Username)
	KeyEncrypt(hmac, "input")

	if !boo {
		return errors.New("list DNE")
	}

	if checkLen(uflistby) {
		return errors.New("file length")
	}

	uflistby, uflistenc, err := hmacevalfunc(hmac, sym, uflistby)

	if err := unmarshalShareList(uflistby, &cflist); checkError(err) {
		return err
	}
	currentEntry, exist := cflist[filename]
	if !exist {
		return errors.New("file DNE")
	}

	cfmetaadd, cfmetakey, cfmetahmac, fmenc, err := FileCopy(Inv{}, currentEntry, false)
	if err != nil {
		return err
	}

	fmbyts, _, err := hmacevalfunc(cfmetahmac, cfmetakey, fmenc)

	if err := unmarshalShareList(fmbyts, &fmeta); checkError(err) {
		return err
	}

	if fmeta.Owner != userdata.Username {
		return errors.New("not owner")
	}

	sharelist, boo := userlib.DatastoreGet(fmeta.ListAdd)
	if !boo {
		return errors.New("Share DNE")
	}
	if err := unmarshalShareList(sharelist, &sharel); checkError(err) {
		return err
	}
	sendershared, exist := sharel[userdata.Username]
	if !exist {
		return errors.New("No invited")
	}

	og, boo, err := findShareEntryByUsername(sendershared, recipientUsername)

	if !boo {
		return errors.New("recipient DNE")
	}

	rev[userdata.Username] = []Share{og}

	processQueue([]string{recipientUsername}, sharel, rev)

	for sender, shareEntries := range sharel {
		if sender == userdata.Username {
			validEntries := filterEntries(shareEntries, recipientUsername)
			validu[sender] = validEntries
			continue
		}

		if _, exists := rev[sender]; !exists {
			validu[sender] = shareEntries
		}
	}

	for _, shareEntries := range rev {
		for _, shareEntry := range shareEntries {
			listadd, listby, exist := FileList(shareEntry.Recieve)
			if !exist {
				return errors.New("Revoke DNE")
			}
			if checkLen(listby) {
				return errors.New("Revoke length")
			}

			SymKey, HMACKey, _ := KeyEncrypt(shareEntry.SourceKey, "userfile")
			_, _, err := hmacevalfunc(HMACKey, SymKey, listby)
			if checkError(err) {
				return err
			}
			userFileList, _, _, exist := DecryptList(uflistenc, SymKey, shareEntry.FileName)

			delete(userFileList, shareEntry.FileName)
			listby, err = json.Marshal(userFileList)
			if checkError(err) {
				return err
			}
			dsset(listby, SymKey, HMACKey, listadd)
		}
	}

	filekey, filehmac, err := KeyEncrypt(userlib.RandomBytes(16), "ListKey")

	if checkError(err) {
		return err
	}

	fnData, err := json.Marshal(fnode)
	dsset(fnData, filekey, filehmac, startadd)

	nfmeta.FileEncKey = filekey
	nfmeta.HMACKey = filehmac
	nfmeta.Start = startadd
	KeyEncrypt(filehmac, "input")
	sharell, err := json.Marshal(validu)
	if checkError(err) {
		return errors.New("marshaling")
	}
	userlib.DatastoreSet(shareladd, sharell)

	nfmeta.Next = fnode.Next
	nfmeta.ListAdd = shareladd

	metaenc, metahmac, err := KeyEncrypt(userlib.RandomBytes(16), "other")
	if err != nil {
		return errors.New("metadata keys")
	}

	metadby, err := json.Marshal(nfmeta)
	dsset(metadby, metaenc, metahmac, metaaddr)

	for _, shareEntries := range validu {
		for _, shareEntry := range shareEntries {
			sym, hmac, _ = KeyEncrypt(userdata.Source, "userfile")
			userList := make(map[string]FxEntry)
			userListadd, userbytes, exist := FileList(shareEntry.Recieve)
			if !exist {
				return errors.New("File DNE")
			}

			if checkLen(userbytes) {
				return errors.New("File Length")
			}

			userbytes, _, _ = hmacevalfunc(hmac, sym, userbytes)

			if err := unmarshalShareList(userbytes, &userList); checkError(err) {
				return err
			}

			fileEntry, exist := userList[shareEntry.FileName]
			if !exist {
				return errors.New("File DNE")
			}

			userList[shareEntry.FileName] = updateFileEntry(metaaddr, metaenc, metahmac, fileEntry)

			userbytes, err = json.Marshal(userList)
			dsset(userbytes, sym, hmac, userListadd)
		}
	}
	cflist[filename] = updateFileEntry(metaaddr, metaenc, metahmac, currentEntry)

	KeyEncrypt(hmac, "input")

	uflistadd, _, _ = FileList(userdata.Username)

	sym, hmac, _ = KeyEncrypt(userdata.Source, "userfile")

	updated, err := json.Marshal(cflist)

	dsset(updated, sym, hmac, uflistadd)

	keysToDelete := []uuid.UUID{fmeta.ListAdd, fmeta.Start, cfmetaadd}
	massDelete(keysToDelete)

	return err
}
func updateFileEntry(addr uuid.UUID, enc []byte, hmac []byte, curr FxEntry) (currentFile FxEntry) {
	curr.MetaAddress = addr
	curr.EncKey = enc
	curr.HMACKey = hmac
	return curr
}

func testerFunc() {
	//_, _, err := userlib.PKEKeyGen()

	originalKey := userlib.RandomBytes(16)
	_, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if checkError(err) {
		panic(err)
	}
	hash := userlib.Hash([]byte("tester"))
	_, err = uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
}
