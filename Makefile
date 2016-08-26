CC = gcc
EXE = cbc
CFLAGS = -Wall

$(EXE): main.o cbc.o ncbc_enc.o set_key.o str2key.o cbc_cksm.o
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o tags $(EXE)
