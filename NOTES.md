# Notes

## Randomness Source

It is your duty to link against the following function:

```
int getentropy(void *buffer, size_t length);
```

This function is part of POSIX 2024 and modern POSIX systems include it in their
libc, so you do not need to do anything. If you are using another system, please
provide this function which, without error when input a valid buffer and a
length < 256, will fill buffer with length bytes of fresh random data.
