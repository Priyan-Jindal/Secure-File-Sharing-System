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

	// Useful for formatting strings (e.g. `
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
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
	// To convert from []byte to string for debugging, use
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
type User struct {
	Username     string
	PasswordHash []byte
	OwnedFiles   []string
	PrivateKey   userlib.PrivateKeyType
	SignKey      userlib.DSSignKey
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Filename   string
	Ciphertext []byte
	Owner      uuid.UUID
	Readers    []uuid.UUID
}

type Share struct {
	Owner     uuid.UUID
	Recipient uuid.UUID
	Readers   []uuid.UUID
	Filename  string
}

type Chunk struct {
	Ciphertext    []byte
	Previouschunk uuid.UUID
	// nonce          string
}

type Append struct {
	Filename    string
	Latestchunk uuid.UUID
	Latestindex int
}

type Invitation struct {
	Sharer            uuid.UUID
	Recipient         uuid.UUID
	SharerFilename    string
	RecipientFilename string
	Status            bool
}

type FilePointer struct {
	SharerFileName    string
	RecipientFileName string
	Sharer            string
	Recipient         string
	IsFile            bool
}

func getHeadFilePointer(userdata *User, filename string) (filePointer FilePointer, err error) {
	filePointerUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename + "fileptr"))[:16])
	var currentFilePointer FilePointer
	if err != nil {
		return currentFilePointer, err
	}
	enc_curr_ptr_bytes, _ := userlib.DatastoreGet(filePointerUUID)

	fileptr_enc_salt := userlib.Hash([]byte(userdata.Username))
	fileptr_mac_salt := userlib.Hash([]byte(userdata.Username))
	fileptr_enc_salt = append(fileptr_enc_salt, []byte("fileptr_symmetric")...)
	fileptr_mac_salt = append(fileptr_mac_salt, userlib.Hash([]byte("fileptr_mac"))...)
	dec_curr_ptr_bytes, err := decryptAndVerify(userdata.Username, fileptr_mac_salt, fileptr_enc_salt, enc_curr_ptr_bytes)
	if err != nil {
		return currentFilePointer, err
	}
	json.Unmarshal(dec_curr_ptr_bytes, &currentFilePointer)

	for !currentFilePointer.IsFile {
		username := currentFilePointer.Sharer

		filePointerUUID, err = uuid.FromBytes(userlib.Hash([]byte(currentFilePointer.Sharer + currentFilePointer.SharerFileName + "fileptr"))[:16])
		enc_curr_ptr_bytes, exists := userlib.DatastoreGet(filePointerUUID)
		if exists == false {
			return currentFilePointer, errors.New("file ptr doesn't exist")
		}
		fileptr_enc_salt := userlib.Hash([]byte(username))
		fileptr_mac_salt := userlib.Hash([]byte(username))
		fileptr_enc_salt = append(fileptr_enc_salt, []byte("fileptr_symmetric")...)
		fileptr_mac_salt = append(fileptr_mac_salt, userlib.Hash([]byte("fileptr_mac"))...)

		dec_curr_ptr_bytes, err = decryptAndVerify(username, fileptr_mac_salt, fileptr_enc_salt, enc_curr_ptr_bytes)
		if err != nil {

			return currentFilePointer, err
		}
		json.Unmarshal(dec_curr_ptr_bytes, &currentFilePointer)
	}

	return currentFilePointer, nil
}

func encryptAndMac(username string, storageKey uuid.UUID, enc_salt []byte, mac_salt []byte, dataBytes []byte) (err error) {

	iv := userlib.RandomBytes(16)
	enc_key := userlib.Argon2Key([]byte(username), enc_salt, 16)
	macKey := userlib.Argon2Key([]byte(username), mac_salt, 16)

	mac_bytes, err := userlib.HMACEval(macKey, dataBytes)

	macUUID, _ := uuid.FromBytes(macKey[:16])
	userlib.DatastoreSet(macUUID, mac_bytes)
	if err != nil {
		return err
	}
	encryptedBytes := userlib.SymEnc(enc_key, iv, dataBytes)
	userlib.DatastoreSet(storageKey, encryptedBytes)

	return nil
}

func decryptAndVerify(username string, mac_salt []byte, dec_salt []byte, data []byte) (decrypted_data []byte, err error) {
	macKey := userlib.Argon2Key([]byte(username), mac_salt, 16)
	macUUID, err := uuid.FromBytes(macKey[:16])
	if err != nil {
		return nil, err
	}
	expected_mac, exists := userlib.DatastoreGet(macUUID)
	if !exists {
		return nil, errors.New("no mac stored")
	}

	dec_key := userlib.Argon2Key([]byte(username), dec_salt, 16)
	dec_data := userlib.SymDec(dec_key, data)
	actual_mac, err := userlib.HMACEval(macKey, dec_data)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expected_mac, actual_mac) {
		return nil, errors.New("struct has been tampered with.")
	}

	return dec_data, nil
}

// NOTE: The following methods have toy (insecure!) implementations.
func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if user already exists in datastore
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])

	if err != nil {
		return nil, err
	}
	_, exists := userlib.DatastoreGet(storageKey)
	if exists {
		return nil, errors.New("User already exists. Please choose a different username.")
	}

	//generate public/private key pair and store public key in keystore
	publicKey, privateKey, err := userlib.PKEKeyGen()
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	usernameHash := userlib.Hash([]byte(username))
	userlib.KeystoreSet(string(usernameHash)+"publicKey", publicKey)

	userlib.KeystoreSet(string(usernameHash)+"verifyKey", verifyKey)

	// encrypt invitation struct (key encryption in helper)

	//create user struct
	var userdata User
	userdata.Username = username
	userdata.PasswordHash = userlib.Hash([]byte(password))
	userdata.SignKey = signKey
	userdata.PrivateKey = privateKey
	userdata.OwnedFiles = []string{}
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	// user struct encryption + mac
	user_enc_salt := userlib.Hash([]byte(username))
	user_mac_salt := userlib.Hash([]byte(username))
	user_enc_salt = append(user_enc_salt, []byte("user_symmetric")...)
	user_mac_salt = append(user_mac_salt, []byte("user_mac")...)
	err = encryptAndMac(username, storageKey, user_enc_salt, user_mac_salt, userBytes)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// query datastore for user struct
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	userData, exists := userlib.DatastoreGet(userUUID)
	if !exists {
		return nil, errors.New("no such user")
	}

	//check mac and decrypt
	user_dec_salt := userlib.Hash([]byte(username))
	user_mac_salt := userlib.Hash([]byte(username))
	user_mac_salt = append(user_mac_salt, []byte("user_mac")...)
	user_dec_salt = append(user_dec_salt, []byte("user_symmetric")...)
	dec_userData, err := decryptAndVerify(username, user_mac_salt, user_dec_salt, userData)
	if err != nil {
		return nil, err
	}
	//return user pointer
	var userdata User
	userdataptr = &userdata
	json.Unmarshal(dec_userData, userdataptr)

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if filename == "aliceFile.txt" {

	}
	if err != nil {
		return err
	}
	// check if file already exists (assuming duplicates are not allowed)
	_, exists := userlib.DatastoreGet(storageKey)
	if exists {
		return err
	}
	// encrypt file contents into ciphertext
	iv := userlib.RandomBytes(16)
	filecontents_enc_salt := userlib.Hash([]byte(userdata.Username))
	filecontents_enc_salt = append(filecontents_enc_salt, []byte("file_cipher_symmetric")...)
	filecontents_enc_key := userlib.Argon2Key([]byte(userdata.Username), filecontents_enc_salt, 16)
	ciphertext := userlib.SymEnc(filecontents_enc_key, iv, content)
	//creating file struct
	var file_struct File
	file_struct.Filename = filename
	file_struct.Ciphertext = ciphertext
	userUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	file_struct.Owner = userUUID
	file_struct.Readers = []uuid.UUID{userUUID}
	fileBytes, err := json.Marshal(file_struct)
	if err != nil {
		return err
	}

	// file struct encryption + mac
	struct_enc_salt := userlib.Hash([]byte(userdata.Username))
	filestruct_mac_salt := userlib.Hash([]byte(userdata.Username))
	struct_enc_salt = append(struct_enc_salt, []byte("file_symmetric")...)
	filestruct_mac_salt = append(filestruct_mac_salt, userlib.Hash([]byte("file_struct_mac"))...)
	err = encryptAndMac(userdata.Username, storageKey, struct_enc_salt, filestruct_mac_salt, fileBytes)
	if err != nil {
		return err
	}

	// create append struct
	append_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(storageKey.String() + "append"))[:16])
	var curr_append Append
	empty_uuid, err := uuid.FromBytes(userlib.Hash([]byte(""))[:16])
	curr_append.Latestchunk = empty_uuid
	curr_append.Filename = filename
	curr_append.Latestindex = 0
	appendBytes, err := json.Marshal(curr_append)
	// encrypt and mac append struct
	append_enc_salt := userlib.Hash([]byte(userdata.Username))
	append_mac_salt := userlib.Hash([]byte(userdata.Username))
	append_enc_salt = append(append_enc_salt, []byte("append_symmetric")...)
	append_mac_salt = append(append_mac_salt, []byte("append_mac")...)
	err = encryptAndMac(userdata.Username, append_storageKey, append_enc_salt, append_mac_salt, appendBytes)
	if err != nil {
		return err
	}

	// decrypt user struct, append file to ownedfiles of user
	username := userdata.Username
	if err != nil {
		return err
	}
	userData, exists := userlib.DatastoreGet(userUUID)
	if !exists {
		return errors.New("no such user")
	}

	//check mac and decrypt
	user_dec_salt := userlib.Hash([]byte(username))
	user_mac_salt := userlib.Hash([]byte(username))
	user_mac_salt = append(user_mac_salt, []byte("user_mac")...)
	user_dec_salt = append(user_dec_salt, []byte("user_symmetric")...)
	dec_userData, err := decryptAndVerify(username, user_mac_salt, user_dec_salt, userData)
	if err != nil {
		return err
	}
	//return user pointer
	var user_data User
	json.Unmarshal(dec_userData, &user_data)
	user_data.OwnedFiles = append(user_data.OwnedFiles, filename)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var username string
	var owner_filename string

	filePointerUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename + "fileptr"))[:16])
	_, exists := userlib.DatastoreGet(filePointerUUID)
	if exists == true {

		head_fileptr, err := getHeadFilePointer(userdata, filename)
		if err != nil {
			return err
		}
		username = head_fileptr.Sharer
		owner_filename = head_fileptr.SharerFileName
	} else {
		username = userdata.Username
		owner_filename = filename
	}

	// decrypt file struct to get readers array
	file_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(owner_filename + username))[:16])

	enc_bytes, exists := userlib.DatastoreGet(file_storageKey)
	if err != nil {
		return err
	}
	if exists == false {
		return errors.New("doesn't exist")
	}

	struct_enc_salt := userlib.Hash([]byte(username))
	filestruct_mac_salt := userlib.Hash([]byte(username))
	struct_enc_salt = append(struct_enc_salt, []byte("file_symmetric")...)
	filestruct_mac_salt = append(filestruct_mac_salt, userlib.Hash([]byte("file_struct_mac"))...)

	// check if file pointer exists (meaning they are not the file owner), set username accordingly

	decBytes, err := decryptAndVerify(username, filestruct_mac_salt, struct_enc_salt, enc_bytes)
	if err != nil {
		return err
	}
	var file_struct File
	json.Unmarshal(decBytes, &file_struct)
	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])

	var valid bool
	for i := 0; i < len(file_struct.Readers); i++ {
		if file_struct.Readers[i] == user_uuid {
			valid = true
			break
		}
	}
	if !valid {
		return errors.New("user does not have permission to access file")
	}
	// grab latest append
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(owner_filename + username))[:16])
	if err != nil {
		return err
	}
	append_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(storageKey.String() + "append"))[:16])
	if err != nil {
		return err
	}
	append_dec_salt := userlib.Hash([]byte(username))
	append_mac_salt := userlib.Hash([]byte(username))
	append_dec_salt = append(append_dec_salt, []byte("append_symmetric")...)
	append_mac_salt = append(append_mac_salt, []byte("append_mac")...)
	enc_appendBytes, ok := userlib.DatastoreGet(append_storageKey)
	if !ok {
		return errors.New("cannot find valid append struct for this file")
	}
	dec_appendBytes, err := decryptAndVerify(username, append_mac_salt, append_dec_salt, enc_appendBytes)
	if err != nil {
		return err
	}

	var append_struct Append
	json.Unmarshal(dec_appendBytes, &append_struct)
	// start making of chunk struct
	latestChunk := append_struct.Latestchunk
	empty_uuid, err := uuid.FromBytes(userlib.Hash([]byte(""))[:16])

	var chunk Chunk
	// add Latestchunk to chunk struct
	if latestChunk == empty_uuid {
		chunk.Previouschunk, err = uuid.FromBytes(userlib.Hash([]byte("first chunk"))[:16])
		if err != nil {
			return err
		}
	} else {
		chunk.Previouschunk = latestChunk
	}

	chunkUUID, err := uuid.FromBytes(userlib.Hash([]byte(chunk.Previouschunk.String() + "chunker" + strconv.Itoa(append_struct.Latestindex)))[:16])
	append_struct.Latestchunk = chunkUUID

	append_struct.Latestindex += 1

	// add ciphertext to chunk struct
	iv := userlib.RandomBytes(16)
	cipher_enc_salt := userlib.Hash([]byte(username))
	cipher_enc_salt = append(cipher_enc_salt, []byte("chunk_cipher_symmetric")...)

	// here
	cipher_enc_key := userlib.Argon2Key([]byte(username), cipher_enc_salt, 16)
	ciphertext := userlib.SymEnc(cipher_enc_key, iv, content)
	chunk.Ciphertext = ciphertext

	// encrypt and mac chunk struct and store on datastore
	chunk_enc_salt := userlib.Hash([]byte(username + strconv.Itoa(append_struct.Latestindex)))
	chunk_mac_salt := userlib.Hash([]byte(username + strconv.Itoa(append_struct.Latestindex)))
	chunk_enc_salt = append(chunk_enc_salt, []byte("chunk_symmetric")...)
	chunk_mac_salt = append(chunk_mac_salt, []byte("chunk_mac")...)

	chunkBytes, err := json.Marshal(chunk)
	err = encryptAndMac(username, chunkUUID, chunk_enc_salt, chunk_mac_salt, chunkBytes)
	if err != nil {
		return err
	}

	// encrypt and mac append struct and store on datastore again
	appendBytes, err := json.Marshal(append_struct)
	err = encryptAndMac(username, append_storageKey, append_dec_salt, append_mac_salt, appendBytes)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var username string
	var file_name string
	filePointerUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename + "fileptr"))[:16])
	_, exists := userlib.DatastoreGet(filePointerUUID)
	if exists == true {
		head_fileptr, err := getHeadFilePointer(userdata, filename)
		if err != nil {
			return nil, err
		}
		username = head_fileptr.Sharer
		file_name = head_fileptr.SharerFileName
	} else {
		username = userdata.Username
		file_name = filename
	}

	// fetch file
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(file_name + username))[:16])
	if err != nil {

		return nil, err
	}
	encrypted_file, exists := userlib.DatastoreGet(storageKey)
	if !exists {

		return nil, err
	}
	//decrypt file
	filestruct_dec_salt := userlib.Hash([]byte(username))
	filestruct_dec_salt = append(filestruct_dec_salt, []byte("file_symmetric")...)

	// check if file pointer exists (meaning they are not the file owner), set username accordingly

	//verify file mac
	filestruct_mac_salt := userlib.Hash([]byte(username))
	filestruct_mac_salt = append(filestruct_mac_salt, userlib.Hash([]byte("file_struct_mac"))...)
	dec_bytes, err := decryptAndVerify(username, filestruct_mac_salt, filestruct_dec_salt, encrypted_file)

	if err != nil {

		return nil, err
	}
	var file_struct File
	err = json.Unmarshal(dec_bytes, &file_struct)
	if err != nil {

		return nil, err
	}
	user_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])

	valid := false

	for i := 0; i < len(file_struct.Readers); i++ {
		if file_struct.Readers[i] == user_storageKey {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errors.New("user does not have permission to access file")
	}
	// decrypt ciphertext from file struct
	ciphertext := file_struct.Ciphertext
	file_dec_salt := userlib.Hash([]byte(username))
	file_dec_salt = append(file_dec_salt, []byte("file_cipher_symmetric")...)
	file_dec_key := userlib.Argon2Key([]byte(username), file_dec_salt, 16)
	plaintext := userlib.SymDec(file_dec_key, ciphertext)
	plaintext_string := string(plaintext)
	// add chunks to plaintext. multiple steps involved
	// STEP ONE -> fetch, decrypt + verify append struct to grab latest append UUID
	append_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(storageKey.String() + "append"))[:16])
	if err != nil {
		return nil, err
	}
	append_dec_salt := userlib.Hash([]byte(username))
	append_mac_salt := userlib.Hash([]byte(username))
	append_dec_salt = append(append_dec_salt, []byte("append_symmetric")...)
	append_mac_salt = append(append_mac_salt, []byte("append_mac")...)
	enc_appendBytes, ok := userlib.DatastoreGet(append_storageKey)
	if !ok {
		return nil, errors.New("cannot find valid append struct for this file")
	}
	dec_appendBytes, err := decryptAndVerify(username, append_mac_salt, append_dec_salt, enc_appendBytes)
	if err != nil {

		return nil, err
	}

	var append_struct Append
	json.Unmarshal(dec_appendBytes, &append_struct)

	Latestchunk_UUID := append_struct.Latestchunk
	empty_uuid, err := uuid.FromBytes(userlib.Hash([]byte(""))[:16])
	if Latestchunk_UUID == empty_uuid {
		return plaintext, nil
	}

	// STEP TWO: iterate through chunks, decrypt chunk, add their plaintext to the plaintext
	appends_plaintext := ""
	index := append_struct.Latestindex
	for {
		enc_curr_chunk_bytes, exists := userlib.DatastoreGet(Latestchunk_UUID)
		if !exists {
			return nil, errors.New("chunk don't exist fam")
		}
		chunk_dec_salt := userlib.Hash([]byte(username + strconv.Itoa(index)))
		chunk_mac_salt := userlib.Hash([]byte(username + strconv.Itoa(index)))
		chunk_dec_salt = append(chunk_dec_salt, []byte("chunk_symmetric")...)
		chunk_mac_salt = append(chunk_mac_salt, []byte("chunk_mac")...)
		dec_chunk_bytes, err := decryptAndVerify(username, chunk_mac_salt, chunk_dec_salt, enc_curr_chunk_bytes)
		if err != nil {
			return nil, err
		}

		var curr_chunk Chunk
		json.Unmarshal(dec_chunk_bytes, &curr_chunk)
		chunk_ciphertext := curr_chunk.Ciphertext
		chunk_cipher_dec_salt := userlib.Hash([]byte(username))
		chunk_cipher_dec_salt = append(chunk_cipher_dec_salt, []byte("chunk_cipher_symmetric")...)
		chunk_dec_key := userlib.Argon2Key([]byte(username), chunk_cipher_dec_salt, 16)
		chunk_plaintext := string(userlib.SymDec(chunk_dec_key, chunk_ciphertext))

		appends_plaintext = chunk_plaintext + appends_plaintext
		first, err := uuid.FromBytes(userlib.Hash([]byte("first chunk"))[:16])
		if curr_chunk.Previouschunk == first {
			break
		}
		Latestchunk_UUID = curr_chunk.Previouschunk
		index -= 1

	}
	plaintext_string = plaintext_string + appends_plaintext

	plaintext_bytes := []byte(plaintext_string)

	//return plaintext

	return plaintext_bytes, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Create new invitation struct
	invitationUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername + filename + "invitation"))[:16])
	var invitation_struct Invitation
	sharerUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	invitation_struct.Sharer = sharerUUID
	invitation_struct.SharerFilename = filename
	invitation_struct.Status = false
	invitationBytes, err := json.Marshal(invitation_struct)
	if err != nil {
		return uuid.New(), err
	}

	// Encrypt, sign, and store invitation struct in datastore

	inv_enc_salt := userlib.Hash([]byte(recipientUsername))
	inv_mac_salt := userlib.Hash([]byte(recipientUsername))
	inv_enc_salt = append(inv_enc_salt, []byte("inv_symmetric")...)
	inv_mac_salt = append(inv_mac_salt, []byte("inv_mac")...)
	// encryption of inv symmetric key
	sym_key := userlib.Argon2Key([]byte(recipientUsername), inv_enc_salt, 16)
	usernameHash := userlib.Hash([]byte(recipientUsername))
	publicKey, exists := userlib.KeystoreGet(string(usernameHash) + "publicKey")
	if exists == false {
		return uuid.New(), errors.New("error")
	}
	sym_key_encrypted, err := userlib.PKEEnc(publicKey, sym_key)

	sym_key_UUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername + "sym_key_UUID"))[:16])
	if err != nil {
		return uuid.New(), err
	}
	userlib.DatastoreSet(sym_key_UUID, sym_key_encrypted)

	iv := userlib.RandomBytes(16)
	encrypted_inv := userlib.SymEnc(sym_key, iv, invitationBytes)
	userlib.DatastoreSet(invitationUUID, encrypted_inv)

	signKey := userdata.SignKey
	signature, err := userlib.DSSign(signKey, invitationBytes)
	if err != nil {
		return uuid.New(), err
	}
	sigUUID, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername + userdata.Username))[:16])
	if err != nil {
		return uuid.New(), err
	}
	userlib.DatastoreSet(sigUUID, signature)

	return invitationUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	enc_invitation, exists := userlib.DatastoreGet(invitationPtr)
	if exists == false {
		return errors.New("ASDfadfasdfa")
	}
	sym_key_UUID, err := uuid.FromBytes(userlib.Hash([]byte(senderUsername + userdata.Username + "sym_key_UUID"))[:16])
	if err != nil {
		return err
	}
	sym_key_enc, exists := userlib.DatastoreGet(sym_key_UUID)
	if exists == false {
		return errors.New("symmetric key encryption does not exist")
	}
	privateKey := userdata.PrivateKey
	sym_key, err := userlib.PKEDec(privateKey, sym_key_enc)
	if err != nil {
		return err
	}
	invBytes := userlib.SymDec(sym_key, enc_invitation)

	sigUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + senderUsername))[:16])
	if err != nil {
		return err
	}
	signature, exists := userlib.DatastoreGet(sigUUID)
	if exists == false {
		return errors.New("error is here")
	}
	usernameHash := userlib.Hash([]byte(senderUsername))
	verify_key, exists := userlib.KeystoreGet(string(usernameHash) + "verifyKey")
	if exists == false {
		return errors.New("no private key found")
	}
	err = userlib.DSVerify(verify_key, invBytes, signature)
	if err != nil {
		return err
	}

	var invitation_struct Invitation
	json.Unmarshal(invBytes, &invitation_struct)

	recipient, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return errors.New("error")
	}
	invitation_struct.Recipient = recipient

	// create file pointer struct
	var filePointer_struct FilePointer
	filePointer_struct.SharerFileName = invitation_struct.SharerFilename
	filePointer_struct.RecipientFileName = filename
	filePointer_struct.Sharer = senderUsername
	filePointer_struct.Recipient = userdata.Username

	// FilePointer stored using RecipientUsername + RecipientFileName
	// Get FilePointer where user is the recipient (since user isn't the owner)
	// If isFile is false, repeat by getting next FilePointer
	// Traverse up FilePoiner structs to find owner and direct connection to get existing Share struct
	curr_filePointerUUID, err := uuid.FromBytes(userlib.Hash([]byte(senderUsername + invitation_struct.SharerFilename + "fileptr"))[:16])
	new_filePointerUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename + "fileptr"))[:16])
	if err != nil {
		return err
	}

	enc_curr_ptr_bytes, exists := userlib.DatastoreGet(curr_filePointerUUID)
	var currentFilePointer FilePointer
	if !exists {

		// create new share struct since this is the original file pointer with isFile set to true
		filePointer_struct.IsFile = true
		currentFilePointer = filePointer_struct
		shareUUID, err := uuid.FromBytes(userlib.Hash([]byte(currentFilePointer.Sharer + currentFilePointer.Recipient + currentFilePointer.SharerFileName + "share_struct"))[:16])
		if err != nil {
			return err
		}

		// Create new share struct
		var share_struct Share
		share_struct.Owner = invitation_struct.Sharer
		share_struct.Recipient = invitation_struct.Recipient
		share_struct.Filename = invitation_struct.SharerFilename
		share_struct.Readers = []uuid.UUID{invitation_struct.Sharer, invitation_struct.Recipient}

		// encrypt, mac, store share struct
		share_enc_salt := userlib.Hash([]byte(senderUsername))
		share_mac_salt := userlib.Hash([]byte(senderUsername))
		share_enc_salt = append(share_enc_salt, []byte("share_symmetric")...)
		share_mac_salt = append(share_mac_salt, []byte("share_mac")...)

		shareBytes, err := json.Marshal(share_struct)
		err = encryptAndMac(senderUsername, shareUUID, share_enc_salt, share_mac_salt, shareBytes)
		if err != nil {
			return err
		}
	} else {

		// Sharer isn't owner so find head FilePointer
		filePointer_struct.IsFile = false
		fileptr_enc_salt := userlib.Hash([]byte(senderUsername))
		fileptr_mac_salt := userlib.Hash([]byte(senderUsername))
		fileptr_enc_salt = append(fileptr_enc_salt, []byte("fileptr_symmetric")...)
		fileptr_mac_salt = append(fileptr_mac_salt, userlib.Hash([]byte("fileptr_mac"))...)
		dec_curr_ptr_bytes, err := decryptAndVerify(senderUsername, fileptr_mac_salt, fileptr_enc_salt, enc_curr_ptr_bytes)
		if err != nil {
			return err
		}
		json.Unmarshal(dec_curr_ptr_bytes, &currentFilePointer)

		for !currentFilePointer.IsFile {
			username := currentFilePointer.Sharer
			curr_filePointerUUID, err = uuid.FromBytes(userlib.Hash([]byte(currentFilePointer.Sharer + currentFilePointer.SharerFileName + "fileptr"))[:16])
			enc_curr_ptr_bytes, exists = userlib.DatastoreGet(curr_filePointerUUID)
			fileptr_enc_salt := userlib.Hash([]byte(username))
			fileptr_mac_salt := userlib.Hash([]byte(username))
			fileptr_enc_salt = append(fileptr_enc_salt, []byte("fileptr_symmetric")...)
			fileptr_mac_salt = append(fileptr_mac_salt, userlib.Hash([]byte("fileptr_mac"))...)

			dec_curr_ptr_bytes, err = decryptAndVerify(username, fileptr_mac_salt, fileptr_enc_salt, enc_curr_ptr_bytes)
			if err != nil {

				return err
			}
			json.Unmarshal(dec_curr_ptr_bytes, &currentFilePointer)
		}

		// Once FilePointer between owner and direct connection is found, get Share struct stored by ownerUsername + recipientUsername + filename
		shareUUID, err := uuid.FromBytes(userlib.Hash([]byte(currentFilePointer.Sharer + currentFilePointer.Recipient + currentFilePointer.SharerFileName + "share_struct"))[:16])

		if err != nil {

			return err
		}
		enc_share_bytes, exists := userlib.DatastoreGet(shareUUID)
		if !exists {
			return errors.New("no share struct brudda")
		}
		share_enc_salt := userlib.Hash([]byte(currentFilePointer.Sharer))
		share_mac_salt := userlib.Hash([]byte(currentFilePointer.Sharer))
		share_enc_salt = append(share_enc_salt, []byte("share_symmetric")...)
		share_mac_salt = append(share_mac_salt, []byte("share_mac")...)

		dec_bytes, err := decryptAndVerify(currentFilePointer.Sharer, share_mac_salt, share_enc_salt, enc_share_bytes)
		if err != nil {

			return err
		}
		var share_struct Share
		json.Unmarshal(dec_bytes, &share_struct)
		share_struct.Readers = append(share_struct.Readers, invitation_struct.Recipient)

		encBytes, err := json.Marshal(share_struct)
		if err != nil {

			return err
		}
		err = encryptAndMac(currentFilePointer.Sharer, shareUUID, share_enc_salt, share_mac_salt, encBytes)
		if err != nil {

			return err
		}
	}
	fileptr_enc_salt := userlib.Hash([]byte(userdata.Username))
	fileptr_mac_salt := userlib.Hash([]byte(userdata.Username))
	fileptr_enc_salt = append(fileptr_enc_salt, []byte("fileptr_symmetric")...)
	fileptr_mac_salt = append(fileptr_mac_salt, userlib.Hash([]byte("fileptr_mac"))...)
	fileptr_bytes, err := json.Marshal(filePointer_struct)
	if err != nil {

		return err
	}
	err = encryptAndMac(userdata.Username, new_filePointerUUID, fileptr_enc_salt, fileptr_mac_salt, fileptr_bytes)
	// Get file struct and add recipient to Readers array

	filestruct_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(currentFilePointer.SharerFileName + currentFilePointer.Sharer))[:16])

	if err != nil {

		return err
	}
	encrypted_file, exists := userlib.DatastoreGet(filestruct_storageKey)
	if !exists {

		return err
	}
	//decrypt/verify file
	filestruct_dec_salt := userlib.Hash([]byte(currentFilePointer.Sharer))
	filestruct_dec_salt = append(filestruct_dec_salt, []byte("file_symmetric")...)
	filestruct_mac_salt := userlib.Hash([]byte(currentFilePointer.Sharer))
	filestruct_mac_salt = append(filestruct_mac_salt, userlib.Hash([]byte("file_struct_mac"))...)
	dec_file_bytes, err := decryptAndVerify(currentFilePointer.Sharer, filestruct_mac_salt, filestruct_dec_salt, encrypted_file)
	if err != nil {

		return err
	}
	var file_struct File
	err = json.Unmarshal(dec_file_bytes, &file_struct)
	if err != nil {

		return err
	}

	// append readers argument of file struct
	file_struct.Readers = append(file_struct.Readers, invitation_struct.Recipient)

	fileBytes, err := json.Marshal(file_struct)
	if err != nil {
		return err
	}
	// file struct encryption + mac
	err = encryptAndMac(currentFilePointer.Sharer, filestruct_storageKey, filestruct_dec_salt, filestruct_mac_salt, fileBytes)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Get share struct with uuid userdata.Username + recipientUsername + filename + "share_struct"
	shareUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername + filename + "share_struct"))[:16])
	if err != nil {
		return err
	}
	enc_share_bytes, exists := userlib.DatastoreGet(shareUUID)
	if !exists {
		return errors.New("no share struct brudda")
	}
	share_enc_salt := userlib.Hash([]byte(userdata.Username))
	share_mac_salt := userlib.Hash([]byte(userdata.Username))
	share_enc_salt = append(share_enc_salt, []byte("share_symmetric")...)
	share_mac_salt = append(share_mac_salt, []byte("share_mac")...)
	dec_bytes, err := decryptAndVerify(userdata.Username, share_mac_salt, share_enc_salt, enc_share_bytes)
	var share_struct Share
	json.Unmarshal(dec_bytes, &share_struct)

	var readers []uuid.UUID
	for i := 0; i < len(share_struct.Readers); i++ {
		if share_struct.Readers[i] != share_struct.Owner {
			readers = append(readers, share_struct.Readers[i])
		}
	}

	// Get the file struct and remove everyone in readers
	filestruct_storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	encrypted_file, exists := userlib.DatastoreGet(filestruct_storageKey)
	if !exists {
		return err
	}
	//decrypt file
	filestruct_dec_salt := userlib.Hash([]byte(userdata.Username))
	filestruct_dec_salt = append(filestruct_dec_salt, []byte("file_symmetric")...)

	//verify file mac
	filestruct_mac_salt := userlib.Hash([]byte(userdata.Username))
	filestruct_mac_salt = append(filestruct_mac_salt, userlib.Hash([]byte("file_struct_mac"))...)
	dec_file_bytes, err := decryptAndVerify(userdata.Username, filestruct_mac_salt, filestruct_dec_salt, encrypted_file)

	if err != nil {
		return err
	}
	var file_struct File
	err = json.Unmarshal(dec_file_bytes, &file_struct)
	if err != nil {
		return err
	}

	// Put all readers that are in file_struct.Readers but not in readers into final list
	final_readers_list := []uuid.UUID{}
	for i := 0; i < len(file_struct.Readers); i++ {
		var in bool
		for j := 0; j < len(readers); j++ {
			if readers[j] == file_struct.Readers[i] {
				in = true
			}
		}
		if in != true {
			final_readers_list = append(final_readers_list, file_struct.Readers[i])
		}
		in = false
	}
	file_struct.Readers = final_readers_list

	// encrypt and store file struct
	fileBytes, err := json.Marshal(file_struct)
	if err != nil {
		return err
	}
	// file struct encryption + mac
	err = encryptAndMac(userdata.Username, filestruct_storageKey, filestruct_dec_salt, filestruct_mac_salt, fileBytes)
	if err != nil {
		return err
	}
	// Delete invitation
	invitationUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername + filename + "invitation"))[:16])
	if err != nil {
		return errors.New("yurrrrrrr")
	}

	userlib.DatastoreDelete(invitationUUID)
	return nil
}
