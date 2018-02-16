## block

```
  struct block: public block_header
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;

  public:
    block(): block_header(), hash_valid(false) {}
    block(const block &b): block_header(b), hash_valid(false), miner_tx(b.miner_tx), tx_hashes(b.tx_hashes) { if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } }
    block &operator=(const block &b) { block_header::operator=(b); hash_valid = false; miner_tx = b.miner_tx; tx_hashes = b.tx_hashes; if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } return *this; }
    void invalidate_hashes() { set_hash_valid(false); }
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }

    transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    // hash cash
    mutable crypto::hash hash;

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
        set_hash_valid(false);

      FIELDS(*static_cast<block_header *>(this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
    END_SERIALIZE()
  };
```

## block\_header

```
  struct block_header
  {
    uint8_t major_version;
    uint8_t minor_version;  // now used as a voting mechanism, rather than how this particular block is built
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
    END_SERIALIZE()
  };
```

## transaction

```
  class transaction: public transaction_prefix
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;
    mutable std::atomic<bool> blob_size_valid;

  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    // hash cash
    mutable crypto::hash hash;
    mutable size_t blob_size;

    transaction();
    transaction(const transaction &t): transaction_prefix(t), hash_valid(false), blob_size_valid(false), signatures(t.signatures), rct_signatures(t.rct_signatures) { if (t.is_hash_valid()) { hash = t.hash; set_hash_valid(true); } if (t.is_blob_size_valid()) { blob_size = t.blob_size; set_blob_size_valid(true); } }
    transaction &operator=(const transaction &t) { transaction_prefix::operator=(t); set_hash_valid(false); set_blob_size_valid(false); signatures = t.signatures; rct_signatures = t.rct_signatures; if (t.is_hash_valid()) { hash = t.hash; set_hash_valid(true); } if (t.is_blob_size_valid()) { blob_size = t.blob_size; set_blob_size_valid(true); } return *this; }
    virtual ~transaction();
    void set_null();
    void invalidate_hashes();
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    bool is_blob_size_valid() const { return blob_size_valid.load(std::memory_order_acquire); }
    void set_blob_size_valid(bool v) const { blob_size_valid.store(v,std::memory_order_release); }

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
      {
        set_hash_valid(false);
        set_blob_size_valid(false);
      }

      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1)
      {
        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.stream().good()) return false;
          ar.end_object();
          if (rct_signatures.type != rct::RCTTypeNull)
          {
            ar.tag("rctsig_prunable");
            ar.begin_object();
            r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout.size(),
                vin.size() > 0 && vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(vin[0]).key_offsets.size() - 1 : 0);
            if (!r || !ar.stream().good()) return false;
            ar.end_object();
          }
        }
      }
    END_SERIALIZE()

    template<bool W, template <bool> class Archive>
    bool serialize_base(Archive<W> &ar)
    {
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1)
      {
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.stream().good()) return false;
          ar.end_object();
        }
      }
      return true;
    }

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };
```

## transaction\_prefix

```
  class transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if(version == 0 || CURRENT_TRANSACTION_VERSION < version) return false;
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
    END_SERIALIZE()

  public:
    transaction_prefix(){}
  };
```

## txin\_v

```
typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key> txin_v;
```

## tx\_out

```
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()


  };
```

## inputs

```
  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };
```

## txout\_target\_v

```
typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key> txout_target_v;
```

## outputs

```
  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };
```

```
namespace cryptonote
{
  struct tx_extra_padding
  {
    size_t size;

    // load
    template <template <bool> class Archive>
    bool do_serialize(Archive<false>& ar)
    {
      // size - 1 - because of variant tag
      for (size = 1; size <= TX_EXTRA_PADDING_MAX_COUNT; ++size)
      {
        std::ios_base::iostate state = ar.stream().rdstate();
        bool eof = EOF == ar.stream().peek();
        ar.stream().clear(state);

        if (eof)
          break;

        uint8_t zero;
        if (!::do_serialize(ar, zero))
          return false;

        if (0 != zero)
          return false;
      }

      return size <= TX_EXTRA_PADDING_MAX_COUNT;
    }

    // store
    template <template <bool> class Archive>
    bool do_serialize(Archive<true>& ar)
    {
      if(TX_EXTRA_PADDING_MAX_COUNT < size)
        return false;

      // i = 1 - because of variant tag
      for (size_t i = 1; i < size; ++i)
      {
        uint8_t zero = 0;
        if (!::do_serialize(ar, zero))
          return false;
      }
      return true;
    }
  };

  struct tx_extra_pub_key
  {
    crypto::public_key pub_key;

    BEGIN_SERIALIZE()
      FIELD(pub_key)
    END_SERIALIZE()
  };

  struct tx_extra_nonce
  {
    std::string nonce;

    BEGIN_SERIALIZE()
      FIELD(nonce)
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size()) return false;
    END_SERIALIZE()
  };

  struct tx_extra_merge_mining_tag
  {
    struct serialize_helper
    {
      tx_extra_merge_mining_tag& mm_tag;

      serialize_helper(tx_extra_merge_mining_tag& mm_tag_) : mm_tag(mm_tag_)
      {
      }

      BEGIN_SERIALIZE()
        VARINT_FIELD_N("depth", mm_tag.depth)
        FIELD_N("merkle_root", mm_tag.merkle_root)
      END_SERIALIZE()
    };

    size_t depth;
    crypto::hash merkle_root;

    // load
    template <template <bool> class Archive>
    bool do_serialize(Archive<false>& ar)
    {
      std::string field;
      if(!::do_serialize(ar, field))
        return false;

      std::istringstream iss(field);
      binary_archive<false> iar(iss);
      serialize_helper helper(*this);
      return ::serialization::serialize(iar, helper);
    }

    // store
    template <template <bool> class Archive>
    bool do_serialize(Archive<true>& ar)
    {
      std::ostringstream oss;
      binary_archive<true> oar(oss);
      serialize_helper helper(*this);
      if(!::do_serialize(oar, helper))
        return false;

      std::string field = oss.str();
      return ::serialization::serialize(ar, field);
    }
  };

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_additional_pub_keys
  {
    std::vector<crypto::public_key> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_mysterious_minergate
  {
    std::string data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  typedef boost::variant<tx_extra_padding, tx_extra_pub_key, tx_extra_nonce, tx_extra_merge_mining_tag, tx_extra_additional_pub_keys, tx_extra_mysterious_minergate> tx_extra_field;
}
```

```
  struct tx_source_entry
  {
    typedef std::pair<uint64_t, rct::ctkey> output_entry;

    std::vector<output_entry> outputs;  //index + key + optional ringct commitment
    size_t real_output;                 //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    std::vector<crypto::public_key> real_out_additional_tx_keys; //incoming real tx additional public keys
    size_t real_output_in_tx_index;     //index in transaction outputs vector
    uint64_t amount;                    //money
    bool rct;                           //true if the output is rct
    rct::key mask;                      //ringct amount mask
    rct::multisig_kLRki multisig_kLRki; //multisig info

    void push_output(uint64_t idx, const crypto::public_key &k, uint64_t amount) { outputs.push_back(std::make_pair(idx, rct::ctkey({rct::pk2rct(k), rct::zeroCommit(amount)}))); }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_additional_tx_keys)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(rct)
      FIELD(mask)
      FIELD(multisig_kLRki)

      if (real_output >= outputs.size())
        return false;
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    uint64_t amount;                    //money
    account_public_address addr;        //destination address
    bool is_subaddress;

    tx_destination_entry() : amount(0), addr(AUTO_VAL_INIT(addr)), is_subaddress(false) { }
    tx_destination_entry(uint64_t a, const account_public_address &ad, bool is_subaddress) : amount(a), addr(ad), is_subaddress(is_subaddress) { }

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(addr)
      FIELD(is_subaddress)
    END_SERIALIZE()
  };
```

## cryptonote

```cpp
/** a pair of <transaction hash, output index>, typedef for convenience */
typedef std::pair<crypto::hash, uint64_t> tx_out_index;
```

```
struct output_data_t
{
  crypto::public_key pubkey;       //!< the output's public key (for spend verification)
  uint64_t           unlock_time;  //!< the output's unlock time (or height)
  uint64_t           height;       //!< the height of the block which created the output
  rct::key           commitment;   //!< the output's amount commitment (for spend verification)
};

struct tx_data_t
{
  uint64_t tx_id;
  uint64_t unlock_time;
  uint64_t block_id;
};

struct txpool_tx_meta_t
{
  crypto::hash max_used_block_id;
  crypto::hash last_failed_id;
  uint64_t blob_size;
  uint64_t fee;
  uint64_t max_used_block_height;
  uint64_t last_failed_height;
  uint64_t receive_time;
  uint64_t last_relayed_time;
  // 112 bytes
  uint8_t kept_by_block;
  uint8_t relayed;
  uint8_t do_not_relay;
  uint8_t double_spend_seen: 1;

  uint8_t padding[76]; // till 192 bytes
};
```



