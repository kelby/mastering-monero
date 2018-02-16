## crypto

```
  POD_CLASS hash {
    char data[HASH_SIZE];
  };
  POD_CLASS hash8 {
    char data[8];
  };
```

```
  POD_CLASS ec_point {
    char data[32];
  };

  POD_CLASS ec_scalar {
    char data[32];
  };

  POD_CLASS public_key: ec_point {
    friend class crypto_ops;
  };

  using secret_key = tools::scrubbed<ec_scalar>;

  POD_CLASS public_keyV {
    std::vector<public_key> keys;
    int rows;
  };

  POD_CLASS secret_keyV {
    std::vector<secret_key> keys;
    int rows;
  };

  POD_CLASS public_keyM {
    int cols;
    int rows;
    std::vector<secret_keyV> column_vectors;
  };

  POD_CLASS key_derivation: ec_point {
    friend class crypto_ops;
  };

  POD_CLASS key_image: ec_point {
    friend class crypto_ops;
  };

  POD_CLASS signature {
    ec_scalar c, r;
    friend class crypto_ops;
  };
```

```
namespace cryptonote
{
  typedef std::string blobdata;
}
```



