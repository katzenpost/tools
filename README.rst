
====================================================
tools that might be useful for mixnet demonstrations
====================================================


GENERATE MIX PKI KEYS
=====================

Generate all the Provider and Mix key material.
Also generate a mix pki json file.


   cd katzenpost/demotools/gen_mixnet_pki

   ./gen_mixnet_pki -keysDir /home/human/projects/mixnet/mix_keys -mixPKIFile /home/human/projects/mixnet/mixpki.json


GENERATE USER PKI KEYS
======================

Generate all the key material used by all the users in the messaging
system.  This command also generates a user PKI json file.

   cd katzenpost/demotools/gen_users

   go build

   MIX_CLIENT_VAULT_PASSPHRASE=DEADBEEFDEADCAFEDEADEADDEAD \
   ./gen_users -userConsensusFile /home/human/projects/mixnet/userpki.json \
   -userKeysDir /home/human/projects/mixnet/user_keys
