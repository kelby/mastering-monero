```
  struct account_keys
  {
    account_public_address m_account_address;
    crypto::secret_key   m_spend_secret_key;
    crypto::secret_key   m_view_secret_key;
    std::vector<crypto::secret_key> m_multisig_keys;
  };
```

```
  struct public_address_outer_blob
  {
    uint8_t m_ver;
    account_public_address m_address;
    uint8_t check_sum;
  };
  struct public_integrated_address_outer_blob
  {
    uint8_t m_ver;
    account_public_address m_address;
    crypto::hash8 payment_id;
    uint8_t check_sum;
  };
```

```
  struct address_parse_info
  {
    account_public_address address;
    bool is_subaddress;
    bool has_payment_id;
    crypto::hash8 payment_id;
  };
```

```
  struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;
  };
```

```
  struct subaddress_receive_info
  {
    subaddress_index index;
    crypto::key_derivation derivation;
  };
```

```
namespace cryptonote
{
  struct subaddress_index
  {
    uint32_t major;
    uint32_t minor;
    bool operator==(const subaddress_index& rhs) const { return !memcmp(this, &rhs, sizeof(subaddress_index)); }
    bool operator!=(const subaddress_index& rhs) const { return !(*this == rhs); }
    bool is_zero() const { return major == 0 && minor == 0; }
  };
}
```

## wallet2

```
    struct multisig_info
    {
      struct LR
      {
        rct::key m_L;
        rct::key m_R;

      };

      crypto::public_key m_signer;
      std::vector<LR> m_LR;
      std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has
    };

    struct tx_scan_info_t
    {
      cryptonote::keypair in_ephemeral;
      crypto::key_image ki;
      rct::key mask;
      uint64_t amount;
      uint64_t money_transfered;
      bool error;
      boost::optional<cryptonote::subaddress_receive_info> received;

      tx_scan_info_t(): money_transfered(0), error(true) {}
    };

    struct transfer_details
    {
      uint64_t m_block_height;
      cryptonote::transaction_prefix m_tx;
      crypto::hash m_txid;
      size_t m_internal_output_index;
      uint64_t m_global_output_index;
      bool m_spent;
      uint64_t m_spent_height;
      crypto::key_image m_key_image; //TODO: key_image stored twice :(
      rct::key m_mask;
      uint64_t m_amount;
      bool m_rct;
      bool m_key_image_known;
      size_t m_pk_index;
      cryptonote::subaddress_index m_subaddr_index;
      bool m_key_image_partial;
      std::vector<rct::key> m_multisig_k;
      std::vector<multisig_info> m_multisig_info; // one per other participant

      bool is_rct() const { return m_rct; }
      uint64_t amount() const { return m_amount; }
      const crypto::public_key &get_public_key() const { return boost::get<const cryptonote::txout_to_key>(m_tx.vout[m_internal_output_index].target).key; }

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_block_height)
        FIELD(m_tx)
        FIELD(m_txid)
        FIELD(m_internal_output_index)
        FIELD(m_global_output_index)
        FIELD(m_spent)
        FIELD(m_spent_height)
        FIELD(m_key_image)
        FIELD(m_mask)
        FIELD(m_amount)
        FIELD(m_rct)
        FIELD(m_key_image_known)
        FIELD(m_pk_index)
        FIELD(m_subaddr_index)
        FIELD(m_key_image_partial)
        FIELD(m_multisig_k)
        FIELD(m_multisig_info)
      END_SERIALIZE()
    };

    struct payment_details
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount;
      uint64_t m_fee;
      uint64_t m_block_height;
      uint64_t m_unlock_time;
      uint64_t m_timestamp;
      cryptonote::subaddress_index m_subaddr_index;
    };

    struct address_tx : payment_details
    {
      bool m_coinbase;
      bool m_mempool;
      bool m_incoming;
    };

    struct pool_payment_details
    {
      payment_details m_pd;
      bool m_double_spend_seen;
    };

    struct unconfirmed_transfer_details
    {
      cryptonote::transaction_prefix m_tx;
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      time_t m_sent_time;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      enum { pending, pending_not_in_pool, failed } m_state;
      uint64_t m_timestamp;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
    };

    struct confirmed_transfer_details
    {
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      uint64_t m_block_height;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      uint64_t m_timestamp;
      uint64_t m_unlock_time;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer

      confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_block_height(0), m_payment_id(crypto::null_hash), m_timestamp(0), m_unlock_time(0), m_subaddr_account((uint32_t)-1) {}
      confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
        m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_block_height(height), m_dests(utd.m_dests), m_payment_id(utd.m_payment_id), m_timestamp(utd.m_timestamp), m_unlock_time(utd.m_tx.unlock_time), m_subaddr_account(utd.m_subaddr_account), m_subaddr_indices(utd.m_subaddr_indices) {}
    };

    struct tx_construction_data
    {
      std::vector<cryptonote::tx_source_entry> sources;
      cryptonote::tx_destination_entry change_dts;
      std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
      std::vector<size_t> selected_transfers;
      std::vector<uint8_t> extra;
      uint64_t unlock_time;
      bool use_rct;
      std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
      uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

      BEGIN_SERIALIZE_OBJECT()
        FIELD(sources)
        FIELD(change_dts)
        FIELD(splitted_dsts)
        FIELD(selected_transfers)
        FIELD(extra)
        FIELD(unlock_time)
        FIELD(use_rct)
        FIELD(dests)
        FIELD(subaddr_account)
        FIELD(subaddr_indices)
      END_SERIALIZE()
    };

    typedef std::vector<transfer_details> transfer_container;
    typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

    struct multisig_sig
    {
      rct::rctSig sigs;
      crypto::public_key ignore;
      std::unordered_set<rct::key> used_L;
      std::unordered_set<crypto::public_key> signing_keys;
      rct::multisig_out msout;
    };

    // The convention for destinations is:
    // dests does not include change
    // splitted_dsts (in construction_data) does
    struct pending_tx
    {
      cryptonote::transaction tx;
      uint64_t dust, fee;
      bool dust_added_to_fee;
      cryptonote::tx_destination_entry change_dts;
      std::vector<size_t> selected_transfers;
      std::string key_images;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;
      std::vector<cryptonote::tx_destination_entry> dests;
      std::vector<multisig_sig> multisig_sigs;

      tx_construction_data construction_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(tx)
        FIELD(dust)
        FIELD(fee)
        FIELD(dust_added_to_fee)
        FIELD(change_dts)
        FIELD(selected_transfers)
        FIELD(key_images)
        FIELD(tx_key)
        FIELD(additional_tx_keys)
        FIELD(dests)
        FIELD(construction_data)
        FIELD(multisig_sigs)
      END_SERIALIZE()
    };

    // The term "Unsigned tx" is not really a tx since it's not signed yet.
    // It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
    struct unsigned_tx_set
    {
      std::vector<tx_construction_data> txes;
      wallet2::transfer_container transfers;
    };

    struct signed_tx_set
    {
      std::vector<pending_tx> ptx;
      std::vector<crypto::key_image> key_images;
    };

    struct multisig_tx_set
    {
      std::vector<pending_tx> m_ptx;
      std::unordered_set<crypto::public_key> m_signers;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_ptx)
        FIELD(m_signers)
      END_SERIALIZE()
    };

    struct keys_file_data
    {
      crypto::chacha_iv iv;
      std::string account_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
      END_SERIALIZE()
    };

    struct cache_file_data
    {
      crypto::chacha_iv iv;
      std::string cache_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(cache_data)
      END_SERIALIZE()
    };

    // GUI Address book
    struct address_book_row
    {
      cryptonote::account_public_address m_address;
      crypto::hash m_payment_id;
      std::string m_description;   
      bool m_is_subaddress;
    };

    struct reserve_proof_entry
    {
      crypto::hash txid;
      uint64_t index_in_tx;
      crypto::public_key shared_secret;
      crypto::key_image key_image;
      crypto::signature shared_secret_sig;
      crypto::signature key_image_sig;
    };

    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;
```



