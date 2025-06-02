// C file with memory issue
#include <stdlib.h>
int main() {
    char *buf = malloc(100);
    printf("Hello");
    return 0;
}
