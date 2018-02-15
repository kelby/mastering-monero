## 环机密交易

```
H_ct = RingCT.getHForCT()
print("H", H_ct)

sr, Pr = PaperWallet.skpkGen() #receivers private/ public
se, pe, ss = ecdh.ecdhgen(Pr) #compute shared secret ss

digits = 14 #in practice it will be 14
print("inputs")
Cia, L1a, s2a, sa, ska = RingCT.genRangeProof(10000, digits)
print("outputs")
Cib, L1b, s2b, sb, skb = RingCT.genRangeProof(7000, digits)
Cic, L1c, s2c, sc, skc = RingCT.genRangeProof(3000, digits)

print("verifying range proofs of outputs")
RingCT.verRangeProof(Cib, L1b, s2b, sb)
RingCT.verRangeProof(Cic, L1c, s2c, sc)

x, P1 = PaperWallet.skpkGen()
P2 = PaperWallet.pkGen()
C2 = PaperWallet.pkGen()

#some random commitment grabbed from the blockchain
ind = 0
Ca = RingCT.sumCi(Cia)
Cb = RingCT.sumCi(Cib)
Cc = RingCT.sumCi(Cic)

sk = [x, MiniNero.sc_sub_keys(ska, MiniNero.sc_add_keys(skb, skc))]
pk = [[P1, P2], [MiniNero.subKeys(Ca, MiniNero.addKeys(Cb, Cc)), MiniNero.subKeys(C2, MiniNero.addKeys(Cb, Cc)) ] ]

II, cc, ssVal = MLSAG.MLSAG_Sign(pk, sk, ind)

print("Sig verified?", MLSAG.MLSAG_Ver(pk, II, cc, ssVal))

print("Finding received amount corresponding to Cib")
RingCT.ComputeReceivedAmount(pe, sr, MiniNero.addScalars(ss, skb), Cib)

print("Finding received amount corresponding to Cic")
RingCT.ComputeReceivedAmount(pe, sr, MiniNero.addScalars(ss, skc), Cic)
```



