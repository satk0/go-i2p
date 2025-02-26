package i2np

import (
	"errors"

	"github.com/sirupsen/logrus"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/session_key"
	"github.com/go-i2p/go-i2p/lib/common/session_tag"
)

/*
I2P I2NP DatabaseLookup
https://geti2p.net/spec/i2np#databaselookup
Accurate for version 0.9.65

+----+----+----+----+----+----+----+----+
| SHA256 hash as the key to look up     |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| SHA256 hash of the routerInfo         |
+ who is asking or the gateway to       +
| send the reply to                     |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|flag| reply_tunnelId    | size    |    |
+----+----+----+----+----+----+----+    +
| SHA256 of key1 to exclude             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                  +----+
|                                  |    |
+----+----+----+----+----+----+----+    +
| SHA256 of key2 to exclude             |
+                                       +
~                                       ~
+                                  +----+
|                                  |    |
+----+----+----+----+----+----+----+    +
|                                       |
+                                       +
|   Session key if reply encryption     |
+   was requested                       +
|                                       |
+                                  +----+
|                                  |tags|
+----+----+----+----+----+----+----+----+
|                                       |
+                                       +
|   Session tags if reply encryption    |
+   was requested                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

key ::
    32 bytes
    SHA256 hash of the object to lookup

from ::
     32 bytes
     if deliveryFlag == 0, the SHA256 hash of the routerInfo entry this
                           request came from (to which the reply should be
                           sent)
     if deliveryFlag == 1, the SHA256 hash of the reply tunnel gateway (to
                           which the reply should be sent)

flags ::
     1 byte
     bit order: 76543210
     bit 0: deliveryFlag
             0  => send reply directly
             1  => send reply to some tunnel
     bit 1: encryptionFlag
             through release 0.9.5, must be set to 0
             as of release 0.9.6, ignored
             as of release 0.9.7:
             0  => send unencrypted reply
             1  => send AES encrypted reply using enclosed key and tag
     bits 3-2: lookup type flags
             through release 0.9.5, must be set to 00
             as of release 0.9.6, ignored
             as of release 0.9.16:
             00  => normal lookup, return RouterInfo or LeaseSet or
                    DatabaseSearchReplyMessage
                    Not recommended when sending to routers
                    with version 0.9.16 or higher.
             01  => LS lookup, return LeaseSet or
                    DatabaseSearchReplyMessage
                    As of release 0.9.38, may also return a
                    LeaseSet2, MetaLeaseSet, or EncryptedLeaseSet.
             10  => RI lookup, return RouterInfo or
                    DatabaseSearchReplyMessage
             11  => exploration lookup, return DatabaseSearchReplyMessage
                    containing non-floodfill routers only (replaces an
                    excludedPeer of all zeroes)
     bit 4: ECIESFlag
             before release 0.9.46 ignored
             as of release 0.9.46:
             0  => send unencrypted or ElGamal reply
             1  => send ChaCha/Poly encrypted reply using enclosed key
                   (whether tag is enclosed depends on bit 1)
     bits 7-5:
             through release 0.9.5, must be set to 0
             as of release 0.9.6, ignored, set to 0 for compatibility with
             future uses and with older routers

reply_tunnelId ::
               4 byte TunnelID
               only included if deliveryFlag == 1
               tunnelId of the tunnel to send the reply to, nonzero

size ::
     2 byte Integer
     valid range: 0-512
     number of peers to exclude from the DatabaseSearchReplyMessage

excludedPeers ::
              $size SHA256 hashes of 32 bytes each (total $size*32 bytes)
              if the lookup fails, these peers are requested to be excluded
              from the list in the DatabaseSearchReplyMessage.
              if excludedPeers includes a hash of all zeroes, the request is
              exploratory, and the DatabaseSearchReplyMessage is requested
              to list non-floodfill routers only.

reply_key ::
     32 byte key
     see below

tags ::
     1 byte Integer
     valid range: 1-32 (typically 1)
     the number of reply tags that follow
     see below

reply_tags ::
     one or more 8 or 32 byte session tags (typically one)
     see below
*/

type DatabaseLookup struct {
	Key           common.Hash
	From          common.Hash
	Flags         byte
	ReplyTunnelID [4]byte
	Size          int
	ExcludedPeers []common.Hash
	ReplyKey      session_key.SessionKey
	Tags          int
	ReplyTags     []session_tag.SessionTag
}

var ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA = errors.New("not enough i2np database lookup data")

func ReadDatabaseLookup(data []byte) (DatabaseLookup, error) {
	log.Debug("Reading DatabaseLookup")
	database_lookup := DatabaseLookup{}

	length := 0
	key, err := readKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Key")
		return database_lookup, err
	}
	database_lookup.Key = key
	length += 32

	from, err := readFrom(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read From")
		return database_lookup, err
	}
	database_lookup.From = from
	length += 32

	flags, err := readFlags(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Flags")
		return database_lookup, err
	}
	database_lookup.Flags = flags
	length += 1

	reply_tunnel_id, err := readReplyTunnelID(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyTunnelID")
		return database_lookup, err
	}
	database_lookup.ReplyTunnelID = reply_tunnel_id
	length += 4

	size, err := readSize(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Size")
		return database_lookup, err
	}
	database_lookup.Size = size
	length += 2

	excluded_peers, err := readExcludedPeers(length, data, size)
	if err != nil {
		log.WithError(err).Error("Failed to read ExcludedPeers")
		return database_lookup, err
	}
	database_lookup.ExcludedPeers = excluded_peers
	length += size * 32

	reply_key, err := readReplyKey(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyKey")
		return database_lookup, err
	}
	database_lookup.ReplyKey = reply_key
	length += 32

	tags, err := readTags(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Tags")
		return database_lookup, err
	}
	database_lookup.Tags = tags
	length += 1

	reply_tags, err := readReplyTags(length, data, tags)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyTags")
		return database_lookup, err
	}
	database_lookup.ReplyTags = reply_tags
	length += tags * 32

	log.Debug("DatabaseLookup read successfully")
	return database_lookup, nil
}

func readKey(data []byte) (common.Hash, error) {
	if len(data) < 32 {
		return common.Hash{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}

	key := common.Hash{}
	copy(key[:], data[:32])

	log.WithFields(logrus.Fields{
		"at":    "i2np.database_lookup.readKey",
		"key":   key,
	}).Debug("parsed_database_lookup_read_key")
	return key, nil
}

func readFrom(length int, data []byte) (common.Hash, error) {
	if len(data) < length + 32 {
		return common.Hash{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	from := common.Hash{}
	copy(from[:], data[length:length + 32])

	log.WithFields(logrus.Fields{
		"at":    "i2np.database_lookup.readFrom",
		"from":   from,
	}).Debug("parsed_database_lookup_read_from")
	return from, nil
}

func readFlags(length int, data []byte) (byte, error) {
	if len(data) < length + 1 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	flags := data[length + 1]

	log.WithFields(logrus.Fields{
		"at":    "i2np.database_lookup.readFlags",
		"from":   flags,
	}).Debug("parsed_database_lookup_read_flags")
	return flags, nil
}

func readReplyTunnelID(length int, data []byte) ([4]byte, error) {
	if len(data) < length + 4 {
		return [4]byte{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	tunnel_id := [4]byte{}
	copy(tunnel_id[:], data[length:length + 4])

	log.WithFields(logrus.Fields{
		"at":          "i2np.database_lookup.readReplyTunnelID",
		"tunnel_id":   tunnel_id,
	}).Debug("parsed_database_lookup_read_reply_tunnel_id")
	return tunnel_id, nil
}

func readSize(length int, data []byte) (int, error) {
	if len(data) < length + 2 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	size := common.Integer(data[length:length + 2]).Int()

	log.WithFields(logrus.Fields{
		"at":          "i2np.database_lookup.readSize",
		"size":   size,
	}).Debug("parsed_database_lookup_read_size")
	return size, nil
}

func readExcludedPeers(length int, data []byte, size int) ([]common.Hash, error) {
	if len(data) < length + size * 32 {
		return []common.Hash{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	var excluded_peers []common.Hash
	for i := 0; i < size; i++ {
		peer := common.Hash{}
		offset := length + i * size
		copy(peer[:], data[offset:offset + 32])
		excluded_peers = append(excluded_peers, peer)
	}

	log.WithFields(logrus.Fields{
		"at":             "i2np.database_lookup.readExcludedPeers",
		"excluded_peers": excluded_peers,
	}).Debug("parsed_database_lookup_read_excluded_peers")
	return excluded_peers, nil
}

func readReplyKey(length int, data []byte) (session_key.SessionKey, error) {
	if len(data) < length + 32 {
		return session_key.SessionKey{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	reply_key := session_key.SessionKey{}
	copy(reply_key[:], data[length:length + 32])

	log.WithFields(logrus.Fields{
		"at":          "i2np.database_lookup.readExcludedPeers",
		"reply_key": reply_key,
	}).Debug("parsed_database_lookup_read_reply_key")
	return reply_key, nil
}

func readTags(length int, data []byte) (int, error) {
	if len(data) < length + 1 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	tags := common.Integer(data[length:length + 1]).Int()

	log.WithFields(logrus.Fields{
		"at":     "i2np.database_lookup.readTags",
		"tags":   tags,
	}).Debug("parsed_database_lookup_read_tags")
	return tags, nil
}

func readReplyTags(length int, data []byte, tags int) ([]session_tag.SessionTag, error) {
	if len(data) < length + tags * 32 {
		return []session_tag.SessionTag{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}
	var reply_tags []session_tag.SessionTag
	for i := 0; i < tags; i++ {
		var tag session_tag.SessionTag
		offset := length + i * tags
		copy(tag[:], data[offset:offset + 32])
		reply_tags = append(reply_tags, tag)
	}

	log.WithFields(logrus.Fields{
		"at":     "i2np.database_lookup.readReplyTags",
		"reply_tags":   reply_tags,
	}).Debug("parsed_database_lookup_read_reply_tags")
	return reply_tags, nil
}
