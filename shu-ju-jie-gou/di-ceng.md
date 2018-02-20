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
/* From fe.h */

typedef int32_t fe[10];

/* From ge.h */

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;
```

## rct

```
    //basic ops containers
    typedef unsigned char * Bytes;

    // Can contain a secret or public key
    //  similar to secret_key / public_key of crypto-ops,
    //  but uses unsigned chars,
    //  also includes an operator for accessing the i'th byte.
    struct key {
        unsigned char bytes[32];
    };
    typedef std::vector<key> keyV; //vector of keys
    typedef std::vector<keyV> keyM; //matrix of keys (indexed by column first)

    //containers For CT operations
    //if it's  representing a private ctkey then "dest" contains the secret key of the address
    // while "mask" contains a where C = aG + bH is CT pedersen commitment and b is the amount
    // (store b, the amount, separately
    //if it's representing a public ctkey, then "dest" = P the address, mask = C the commitment
    struct ctkey {
        key dest;
        key mask; //C here if public
    };
    typedef std::vector<ctkey> ctkeyV;
    typedef std::vector<ctkeyV> ctkeyM;

    //used for multisig data
    struct multisig_kLRki {
        key k;
        key L;
        key R;
        key ki;
    };

    struct multisig_out {
        std::vector<key> c; // for all inputs
    };

    //data for passing the amount to the receiver secretly
    // If the pedersen commitment to an amount is C = aG + bH,
    // "mask" contains a 32 byte key a
    // "amount" contains a hex representation (in 32 bytes) of a 64 bit number
    // "senderPk" is not the senders actual public key, but a one-time public key generated for
    // the purpose of the ECDH exchange
    struct ecdhTuple {
        key mask;
        key amount;
        key senderPk;
    };

    //containers for representing amounts
    typedef uint64_t xmr_amount;
    typedef unsigned int bits[ATOMS];
    typedef key key64[64];

    struct boroSig {
        key64 s0;
        key64 s1;
        key ee;
    };

    //Container for precomp
    struct geDsmp {
        ge_dsmp k;
    };

    //just contains the necessary keys to represent MLSAG sigs
    //c.f. http://eprint.iacr.org/2015/1098
    struct mgSig {
        keyM ss;
        key cc;
        keyV II;
    };
    //contains the data for an Borromean sig
    // also contains the "Ci" values such that
    // \sum Ci = C
    // and the signature proves that each Ci is either
    // a Pedersen commitment to 0 or to 2^i
    //thus proving that C is in the range of [0, 2^64]
    struct rangeSig {
        boroSig asig;
        key64 Ci;
    };

    struct Bulletproof
    {
      rct::keyV V;
      rct::key A, S, T1, T2;
      rct::key taux, mu;
      rct::keyV L, R;
      rct::key a, b, t;
    };

    //A container to hold all signatures necessary for RingCT
    // rangeSigs holds all the rangeproof data of a transaction
    // MG holds the MLSAG signature of a transaction
    // mixRing holds all the public keypairs (P, C) for a transaction
    // ecdhInfo holds an encoded mask / amount to be passed to each receiver
    // outPk contains public keypairs which are destinations (P, C),
    //  P = address, C = commitment to amount
    enum {
      RCTTypeNull = 0,
      RCTTypeFull = 1,
      RCTTypeSimple = 2,
      RCTTypeFullBulletproof = 3,
      RCTTypeSimpleBulletproof = 4,
    };
    struct rctSigBase {
        uint8_t type;
        key message;
        ctkeyM mixRing; //the set of all pubkeys / copy
        //pairs that you mix with
        keyV pseudoOuts; //C - for simple rct
        std::vector<ecdhTuple> ecdhInfo;
        ctkeyV outPk;
        xmr_amount txnFee; // contains b
    };
    struct rctSigPrunable {
        std::vector<rangeSig> rangeSigs;
        std::vector<Bulletproof> bulletproofs;
        std::vector<mgSig> MGs; // simple rct has N, full has 1
    };
    struct rctSig: public rctSigBase {
        rctSigPrunable p;
    };
```

## cryptonote

```
  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    static inline keypair generate()
    {
      keypair k;
      generate_keys(k.pub, k.sec);
      return k;
    }
  };
```

```
  typedef std::vector<crypto::signature> ring_signature;
```

```
{
  typedef std::string blobdata;
}
```



