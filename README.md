# parallel-search-keyspace

 Executes a parallel process brute force attack against an RSA encryption key.
 
 Note: Binary keys containing \0 cannot currently be processed because
 input arguments are split on the null character.  To resolve this issue,
 we would need to read the key from stdin, or from a file.  At the moment,
 however, command line arguments should be sufficient.
 
 returns: output the key to stdout on success, nothing on failure
 
