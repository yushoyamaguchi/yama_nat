OBJS=main.o netutil.o ip2mac.o sendBuf.o json_config.o tree.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=-lpthread -ljansson
TARGET=yama_router
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

IMG := yama_router:test
docker-build:
	docker build --no-cache -t $(IMG)  .
