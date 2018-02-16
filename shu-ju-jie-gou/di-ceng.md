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
        unsigned char & operator[](int i) {
            return bytes[i];
        }
        unsigned char operator[](int i) const {
            return bytes[i];
        }
        bool operator==(const key &k) const { return !memcmp(bytes, k.bytes, sizeof(bytes)); }
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

        BEGIN_SERIALIZE_OBJECT()
          FIELD(c)
        END_SERIALIZE()
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

        BEGIN_SERIALIZE_OBJECT()
          FIELD(mask)
          FIELD(amount)
          // FIELD(senderPk) // not serialized, as we do not use it in monero currently
        END_SERIALIZE()
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

        BEGIN_SERIALIZE_OBJECT()
            FIELD(ss)
            FIELD(cc)
            // FIELD(II) - not serialized, it can be reconstructed
        END_SERIALIZE()
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

        BEGIN_SERIALIZE_OBJECT()
            FIELD(asig)
            FIELD(Ci)
        END_SERIALIZE()
    };

    struct Bulletproof
    {
      rct::keyV V;
      rct::key A, S, T1, T2;
      rct::key taux, mu;
      rct::keyV L, R;
      rct::key a, b, t;

      Bulletproof() {}
      Bulletproof(const rct::key &V, const rct::key &A, const rct::key &S, const rct::key &T1, const rct::key &T2, const rct::key &taux, const rct::key &mu, const rct::keyV &L, const rct::keyV &R, const rct::key &a, const rct::key &b, const rct::key &t):
        V({V}), A(A), S(S), T1(T1), T2(T2), taux(taux), mu(mu), L(L), R(R), a(a), b(b), t(t) {}

      BEGIN_SERIALIZE_OBJECT()
        // Commitments aren't saved, they're restored via outPk
        // FIELD(V)
        FIELD(A)
        FIELD(S)
        FIELD(T1)
        FIELD(T2)
        FIELD(taux)
        FIELD(mu)
        FIELD(L)
        FIELD(R)
        FIELD(a)
        FIELD(b)
        FIELD(t)

        if (L.empty() || L.size() != R.size())
          return false;
      END_SERIALIZE()
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

        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_base(Archive<W> &ar, size_t inputs, size_t outputs)
        {
          FIELD(type)
          if (type == RCTTypeNull)
            return true;
          if (type != RCTTypeFull && type != RCTTypeFullBulletproof && type != RCTTypeSimple && type != RCTTypeSimpleBulletproof)
            return false;
          VARINT_FIELD(txnFee)
          // inputs/outputs not saved, only here for serialization help
          // FIELD(message) - not serialized, it can be reconstructed
          // FIELD(mixRing) - not serialized, it can be reconstructed
          if (type == RCTTypeSimple || type == RCTTypeSimpleBulletproof)
          {
            ar.tag("pseudoOuts");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, pseudoOuts);
            if (pseudoOuts.size() != inputs)
              return false;
            for (size_t i = 0; i < inputs; ++i)
            {
              FIELDS(pseudoOuts[i])
              if (inputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }

          ar.tag("ecdhInfo");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, ecdhInfo);
          if (ecdhInfo.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            FIELDS(ecdhInfo[i])
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();

          ar.tag("outPk");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, outPk);
          if (outPk.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            FIELDS(outPk[i].mask)
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();
          return true;
        }
    };
    struct rctSigPrunable {
        std::vector<rangeSig> rangeSigs;
        std::vector<Bulletproof> bulletproofs;
        std::vector<mgSig> MGs; // simple rct has N, full has 1

        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_prunable(Archive<W> &ar, uint8_t type, size_t inputs, size_t outputs, size_t mixin)
        {
          if (type == RCTTypeNull)
            return true;
          if (type != RCTTypeFull && type != RCTTypeFullBulletproof && type != RCTTypeSimple && type != RCTTypeSimpleBulletproof)
            return false;
          if (type == RCTTypeSimpleBulletproof || type == RCTTypeFullBulletproof)
          {
            ar.tag("bp");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, bulletproofs);
            if (bulletproofs.size() != outputs)
              return false;
            for (size_t i = 0; i < outputs; ++i)
            {
              FIELDS(bulletproofs[i])
              if (outputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }
          else
          {
            ar.tag("rangeSigs");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, rangeSigs);
            if (rangeSigs.size() != outputs)
              return false;
            for (size_t i = 0; i < outputs; ++i)
            {
              FIELDS(rangeSigs[i])
              if (outputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }

          ar.tag("MGs");
          ar.begin_array();
          // we keep a byte for size of MGs, because we don't know whether this is
          // a simple or full rct signature, and it's starting to annoy the hell out of me
          size_t mg_elements = (type == RCTTypeSimple || type == RCTTypeSimpleBulletproof) ? inputs : 1;
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(mg_elements, MGs);
          if (MGs.size() != mg_elements)
            return false;
          for (size_t i = 0; i < mg_elements; ++i)
          {
            // we save the MGs contents directly, because we want it to save its
            // arrays and matrices without the size prefixes, and the load can't
            // know what size to expect if it's not in the data
            ar.begin_object();
            ar.tag("ss");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(mixin + 1, MGs[i].ss);
            if (MGs[i].ss.size() != mixin + 1)
              return false;
            for (size_t j = 0; j < mixin + 1; ++j)
            {
              ar.begin_array();
              size_t mg_ss2_elements = ((type == RCTTypeSimple || type == RCTTypeSimpleBulletproof) ? 1 : inputs) + 1;
              PREPARE_CUSTOM_VECTOR_SERIALIZATION(mg_ss2_elements, MGs[i].ss[j]);
              if (MGs[i].ss[j].size() != mg_ss2_elements)
                return false;
              for (size_t k = 0; k < mg_ss2_elements; ++k)
              {
                FIELDS(MGs[i].ss[j][k])
                if (mg_ss2_elements - k > 1)
                  ar.delimit_array();
              }
              ar.end_array();

              if (mixin + 1 - j > 1)
                ar.delimit_array();
            }
            ar.end_array();

            ar.tag("cc");
            FIELDS(MGs[i].cc)
            // MGs[i].II not saved, it can be reconstructed
            ar.end_object();

            if (mg_elements - i > 1)
               ar.delimit_array();
          }
          ar.end_array();
          return true;
        }

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



