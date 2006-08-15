This branch is basically aimed to following:
1. Extend existing suppotred protocol on Shareaza
2. optimize network core

for first aim, currently plainning to extend Gnutella and Gnutella2 protocol. such as:
* adding Gnutella UDP support
* adding some protocol like UDPHC on Gnutella2 (KHL over UDP, using KHLR and KHLA)
* find and solve problem that search Gnutella2 protocol from Firewalled node is not working as good as what it should do.
* add something similar to push-proxy for G2. (using X-G2NH tag on HTTP header)

for the second, it is just optimize some code on shareaza to boost up speed. some optimization has been implemented and in testing phase. things has been done already are:
* optimization on Query Hash Table lookup.
* optimization on Array of Transfer (CTransfers class) using std::list.


These are the things been planned or has been done on this branch.
