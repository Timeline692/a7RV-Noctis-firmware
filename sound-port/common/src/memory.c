/* Omit this object when the embedding module already supplies these symbols. */
#include <stddef.h>
void *memcpy(void *destination,const void *source,size_t bytes){
    unsigned char *d=destination;const unsigned char *s=source;
    for(size_t i=0;i<bytes;i++)d[i]=s[i];return destination;
}
void *memset(void *destination,int value,size_t bytes){
    unsigned char *d=destination;
    for(size_t i=0;i<bytes;i++)d[i]=(unsigned char)value;return destination;
}
int memcmp(const void *a,const void *b,size_t bytes){
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<bytes;i++)if(x[i]!=y[i])return (int)x[i]-(int)y[i];return 0;
}
