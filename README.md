agefs
=====

## Limitation

(WIP)

* if you use hardlink, all filenames are consistent about whether or not encrypt the target file.
* unencrpyted file size are set as xattr named `user.agefs_decrypted_size`.
    * this xattr is not deleted when the file becomes non encrypt target with modifying .ageignore file.
