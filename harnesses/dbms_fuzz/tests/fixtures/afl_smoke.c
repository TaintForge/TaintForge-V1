#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

int main(void) {
  uint8_t input[8] = {0};
  ssize_t length = read(STDIN_FILENO, input, sizeof(input));

  if (length >= 4 && input[0] == 'A' && input[1] == 'F' &&
      input[2] == 'L' && input[3] == '+') {
    return 1;
  }
  return 0;
}
