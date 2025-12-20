
FROM alpine:latest AS builder

RUN apk add --no-cache build-base

WORKDIR /build

COPY . .

RUN gcc zhttpd_std.c -o zhttpd -std=c11 -O2 -I. -D_POSIX_C_SOURCE=200809L -ldl

RUN for f in modules/*.c; do \
        gcc -shared -fPIC -o ${f%.c}.so $f -O2 -std=c11 \
        -DZNET_IMPLEMENTATION \
        -DZTHREAD_IMPLEMENTATION \
        -DZSTR_IMPLEMENTATION \
        -DZFILE_IMPLEMENTATION \
        -DZERROR_IMPLEMENTATION; \
    done

FROM alpine:latest

RUN adduser -D zuser
USER zuser

WORKDIR /home/zuser/www

COPY --from=builder /build/zhttpd /usr/local/bin/zhttpd

COPY --from=builder /build/modules/*.so /home/zuser/www/modules/

COPY --from=builder /build/*.conf /home/zuser/www/
COPY site/ . 

EXPOSE 8080

CMD ["zhttpd", "."]
