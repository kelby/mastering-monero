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



