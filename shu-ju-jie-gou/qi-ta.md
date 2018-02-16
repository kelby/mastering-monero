## cryptonote

```
typedef std::uint64_t difficulty_type;
```

```
namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct tx_verification_context
  {
    bool m_should_be_relayed;
    bool m_verifivation_failed; //bad tx, should drop connection
    bool m_verifivation_impossible; //the transaction is related with an alternative blockchain
    bool m_added_to_pool; 
    bool m_low_mixin;
    bool m_double_spend;
    bool m_invalid_input;
    bool m_invalid_output;
    bool m_too_big;
    bool m_overspend;
    bool m_fee_too_low;
    bool m_not_rct;
  };

  struct block_verification_context
  {
    bool m_added_to_main_chain;
    bool m_verifivation_failed; //bad block, should drop connection
    bool m_marked_as_orphaned;
    bool m_already_exists;
    bool m_partial_block_reward;
  };
}
```

```
  typedef std::pair<std::pair<double, std::time_t>, crypto::hash> tx_by_fee_and_receive_time_entry;
  typedef std::set<tx_by_fee_and_receive_time_entry, txCompare> sorted_tx_container;
```

```
typedef struct mdb_block_info
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_size; // a size_t really but we need 32-bit compat
  difficulty_type bi_diff;
  crypto::hash bi_hash;
} mdb_block_info;

typedef struct blk_height {
    crypto::hash bh_hash;
    uint64_t bh_height;
} blk_height;

typedef struct txindex {
    crypto::hash key;
    tx_data_t data;
} txindex;

typedef struct pre_rct_outkey {
    uint64_t amount_index;
    uint64_t output_id;
    pre_rct_output_data_t data;
} pre_rct_outkey;

typedef struct outkey {
    uint64_t amount_index;
    uint64_t output_id;
    output_data_t data;
} outkey;

typedef struct outtx {
    uint64_t output_id;
    crypto::hash tx_hash;
    uint64_t local_index;
} outtx;
```



