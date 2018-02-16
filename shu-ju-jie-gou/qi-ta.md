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



