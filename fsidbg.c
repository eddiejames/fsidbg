/*
 * Copyright 2017 IBM Corporation
 *
 * Eddie James <eajames@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum device_type {
	RAW,
	SCOM,
	I2C,
	SBEFIFO,
	OCC,
	NUM_DEVICE_TYPES
};

static const char *device_type_names[NUM_DEVICE_TYPES] = {
	"raw",
	"scom",
	"i2c",
	"sbefifo",
	"occ",
};

typedef int(*do_fsi_op)(int argc, char **argv, char *dev);

void get_data(uint8_t *buf, unsigned long size, char *arg)
{
	unsigned int i, count = strlen(arg);
	char c;
	uint8_t n;

	for (i = 0; i < count && (i / 2) < size; ++i) {
		c = arg[i];

		if (c >= '0' && c <= '9')
			n = c - '0';
		else if (c >= 'a' && c <= 'f')
			n = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			n = c - 'A' + 10;
		else
			n = 0;

		if (!(i % 2))
			buf[i / 2] = n << 4;
		else
			buf[i / 2] |= n;
	}
}

int arg_to_uint(char *arg, unsigned long *val)
{
	unsigned long tval;

	errno = 0;
	tval = strtoul(arg, NULL, 0);
	if (errno) {
		printf("couldn't parse arg %s\n", arg);
		return -1;
	}

	*val = tval;
	return 0;
}

int arg_to_uint64(char *arg, uint64_t *val)
{
	uint64_t tval;

	errno = 0;
	tval = strtoull(arg, NULL, 0);
	if (errno) {
		printf("couldn't parse arg %s\n", arg);
		return -1;
	}

	*val = tval;
	return 0;
}

void display_buf(uint8_t *buf, unsigned long size)
{
	unsigned long i;

	for (i = 0; i < size; ++i) {
		printf("%02X ", buf[i]);
		if (!((i + 1) % 16))
			printf("\n");
	}
	if (i % 16)
		printf("\n");
}

int detect_device_type(char *dev)
{
	int i;
	char *found;

	for (i = 0; i < NUM_DEVICE_TYPES; ++i) {
		found = strstr(dev, device_type_names[i]);
		if (found)
			return i;
	}

	return -1;
}

const char *raw_help =
	"fsidbg raw FSI device:\n"
	"-r --read <x>			read 4 bytes from address x\n"
	"-w --write <x>			write 4 bytes to address x\n"
	"-d --date <x>			specify data for write op\n"
	"Example:\n"
	"    fsidbg /sys/devices/platform/gpio-fsi/fsi0/slave@00:00\\raw -r "
		"0x181C\n"
	"        Read I2C status register\n";

int do_raw(int argc, char **argv, char *dev)
{
	enum command_type {
		READ,
		WRITE,
		NUM_COMMAND_TYPES
	};

	char set_data = 0;
	int fd, rc = 0, cmd = -1, option;
	unsigned long address = 0, data, data_be;
	const char *opts = "r:w:d:h";
	struct option lopts[] = {
		{ "read", 1, 0, 'r' },
		{ "write", 1, 0, 'w' },
		{ "data", 1, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("couldn't open device %s: %s\n", dev, strerror(errno));
		return -ENODEV;
	}

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'w':
			cmd = WRITE;
			if ((rc = arg_to_uint(optarg, &address)))
				goto done;
			break;
		case 'r':
			cmd = READ;
			if ((rc = arg_to_uint(optarg, &address)))
				goto done;
			break;
		case 'd':
			set_data = 1;
			if ((rc = arg_to_uint(optarg, &data)))
				goto done;
			break;
		case 'h':
			printf("%s", raw_help);
			goto done;
		default:
			printf("unknown option %c\n", option);
		}
	}

	rc = lseek(fd, address, SEEK_SET);
	if (rc < 0) {
		printf("failed to seek %08lX: %s\n", address, strerror(errno));
		goto done;
	}

	switch (cmd) {
	case READ:
		rc = read(fd, &data_be, 4);
		if (rc < 0) {
			printf("failed to read from %08lx: %s\n", address,
			       strerror(errno));
			goto done;
		}

		data = be32toh(data_be);
		printf("%08lX\n", data);
		break;
	case WRITE:
		if (!set_data) {
			printf("attempted write without data; abort\n");
			goto done;
		}

		data_be = htobe32(data);
		rc = write(fd, &data_be, 4);
		if (rc < 0) {
			printf("failed to write %08lX to %08lX: %s\n", data,
			       address, strerror(errno));
			goto done;
		}

		printf("wrote %08lX to %08lX\n", data, address);
		break;
	default:
		printf("unknown command\n");
		rc = -1;
	}

done:
	close(fd);

	return rc;
}

const char *scom_help =
	"fsidbg SCOM device:\n"
	"-r --read <x>			getscom from address x\n"
	"-w --write <x>			putscom to address x\n"
	"-d --date <x>			specify data for putscom op\n"
	"Example:\n"
	"    fsidbg /dev/scom1 -r 0x6D051\n"
	"        Fetches 8 bytes from 0x6D051\n";

int do_scom(int argc, char **argv, char *dev)
{
	enum command_type {
		READ,
		WRITE,
		NUM_COMMAND_TYPES
	};

	char set_data = 0;
	int fd, rc = 0, cmd = -1, option;
	uint32_t address;
	uint64_t address64 = 0ULL, data;
	const char *opts = "r:w:d:h";
	struct option lopts[] = {
		{ "read", 1, 0, 'r' },
		{ "write", 1, 0, 'w' },
		{ "data", 1, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("couldn't open device %s: %s\n", dev, strerror(errno));
		return -ENODEV;
	}

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'w':
			cmd = WRITE;
			if ((rc = arg_to_uint64(optarg, &address64)))
				goto done;
			break;
		case 'r':
			cmd = READ;
			if ((rc = arg_to_uint64(optarg, &address64)))
				goto done;
			break;
		case 'd':
			set_data = 1;
			if ((rc = arg_to_uint64(optarg, &data)))
				goto done;
			break;
		case 'h':
			printf("%s", scom_help);
			goto done;
		default:
			printf("unknown option %c\n", option);
		}
	}

	/* TODO: indirect scom */
	if (address64 > 0xFFFFFFFFULL) {
		printf("indirect addressing not supported; abort\n");
		goto done;
	}

	address = address64;

	rc = lseek(fd, address, SEEK_SET);
	if (rc < 0) {
		printf("failed to seek %08X: %s\n", address, strerror(errno));
		goto done;
	}

	switch (cmd) {
	case READ:
		rc = read(fd, &data, 8);
		if (rc < 0) {
			printf("failed to read from %08X: %s\n", address,
			       strerror(errno));
			goto done;
		}

		printf("%016llX\n", data);
		break;
	case WRITE:
		if (!set_data) {
			printf("attempted write without data; abort\n");
			goto done;
		}

		rc = write(fd, &data, 8);
		if (rc < 0) {
			printf("failed to write %016llX to %08X: %s\n", data,
			       address, strerror(errno));
			goto done;
		}

		printf("wrote %016llX to %08X\n", data, address);
		break;
	default:
		printf("unknown command\n");
		rc = -1;
	}

done:
	close(fd);

	return rc;
}

const char *i2c_help =
	"fsidbg I2C device:\n"
	"-r --read <x>			do read op of x bytes\n"
	"-w --write <x>			do write op of x bytes\n"
	"-a --address <x>		use I2C device address x\n"
	"-s --scan			scan bus for devices\n"
	"-d --data x			specify data, in hex bytes\n"
	"-o --offset <x>			specify offset; if you want a "
		"specific\n"
	"				device width option, you need to make "
		"your\n"
	"				offset the appropriate width. (e.g. -o"
		" 0000\n"
	"				will give you 2 bytes offset)\n"
	"-t --timeout <x>		specify timeout in ms (default 1000)\n"
	"Example:\n"
	"    fsidbg /dev/i2c-100 -a 0xA0 -o 0000 -r 4\n"
	"        Reads 4 bytes from offset 0 of 0xA0 on /dev/i2c-100\n";

int do_i2c(int argc, char **argv, char *dev)
{
	enum command_type {
		READ,
		WRITE,
		SCAN,
		NUM_COMMAND_TYPES
	};

	int fd, rc = 0, cmd = -1, option;
	uint8_t offset8;
	uint16_t offset16;
	uint32_t offset32;
	uint8_t address, offset_width = 0;
	uint8_t *data;
	unsigned long size = 0;
	char *arg_data = NULL;
	void *offset = NULL;
	const char *opts = "r:w:sa:d:o:t:h";
	struct option lopts[] = {
		{ "read", 1, 0, 'r' },
		{ "write", 1, 0, 'w' },
		{ "scan", 0, 0, 's' },
		{ "address", 1, 0, 'a' },
		{ "data", 1, 0, 'd' },
		{ "offset", 1, 0, 'o' },
		{ "timeout", 1, 0, 't' },
		{ "help", 0, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("couldn't open device %s: %s\n", dev, strerror(errno));
		return -ENODEV;
	}

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		unsigned long tmp = 0;

		switch (option) {
		case 'r':
			cmd = READ;
			if ((rc = arg_to_uint(optarg, &size)))
				goto free;

			if (!size) {
				printf("bad size\n");
				rc = -1;
				goto free;
			}
			break;
		case 'w':
			cmd = WRITE;
			if ((rc = arg_to_uint(optarg, &size)))
				goto free;

			if (!size) {
				printf("bad size\n");
				rc = -1;
				goto free;
			}
			break;
		case 's':
			cmd = SCAN;
			break;
		case 'a':
			if ((rc = arg_to_uint(optarg, &tmp)))
				goto free;

			if (tmp > 0xFF) {
				printf("bad address %ld\n", tmp);
				rc = -ENODEV;
				goto free;
			}

			address = tmp;
			break;
		case 'd':
			arg_data = malloc(strlen(optarg) + 1);
			if (!arg_data) {
				rc = -ENOMEM;
				goto close;
			}

			strcpy(arg_data, optarg);
			break;
		case 'o':
		{
			char *found;
			unsigned long arg_offset;

			if ((rc = arg_to_uint(optarg, &arg_offset)))
				goto free;

			offset_width = (strlen(optarg) + 1) / 2;

			found = strstr(optarg, "0x");
			if (found)
				offset_width--;

			switch (offset_width) {
			case 1:
				offset8 = arg_offset;
				offset = &offset8;
				break;
			case 2:
				offset16 = htobe16(arg_offset);
				offset = &offset16;
				break;
			case 3:
				offset_width = 4;
			case 4:
				offset32 = htobe32(arg_offset);
				offset = &offset32;
				break;
			}
		}
			break;
		case 't':
			if ((rc = arg_to_uint(optarg, &tmp)))
				goto free;

			if (tmp >= 10)
				ioctl(fd, I2C_TIMEOUT, tmp / 10);
			break;
		case 'h':
			printf("%s", i2c_help);
			goto free;
		default:
			printf("unknown option %c\n", option);
		}
	}

	data = malloc(size + 4);
	if (!data) {
		rc = -ENOMEM;
		goto free;
	}

	memset(data, 0, size + 4);

	if (cmd == WRITE && arg_data) {
		if (offset_width)
			memcpy(data, offset, offset_width);

		get_data(data + offset_width, size, arg_data);
	}

	ioctl(fd, I2C_TENBIT, 1);

	switch (cmd) {
	case READ:
	{
		unsigned int i = 0;
		struct i2c_rdwr_ioctl_data rdwr;
		struct i2c_msg *fmsgs = NULL;

		if (size > 8192) {
			unsigned int num_msgs = (size / 8192) + 1;
			unsigned int total = 0;

			if (offset_width)
				num_msgs++;

			fmsgs = malloc(sizeof(struct i2c_msg) * num_msgs);
			memset(fmsgs, 0, sizeof(struct i2c_msg) * num_msgs);

			if (offset_width) {
				fmsgs[0].addr = address;
				fmsgs[0].flags = I2C_M_TEN;
				fmsgs[0].len = offset_width;
				fmsgs[0].buf = offset;

				i++;
			}

			for (; i < num_msgs - 1; ++i) {
				fmsgs[i].addr = address;
				fmsgs[i].flags = I2C_M_TEN | I2C_M_RD;
				fmsgs[i].len = 8192;
				fmsgs[i].buf = &data[total];

				total += 8192;
			}

			fmsgs[i].addr = address;
			fmsgs[i].flags = I2C_M_TEN | I2C_M_STOP | I2C_M_RD;
			fmsgs[i].len = size - total;
			fmsgs[i].buf = &data[total];

			rdwr.nmsgs = num_msgs;
			rdwr.msgs = fmsgs;
		}
		else if (offset_width) {
			struct i2c_msg msgs[2];

			msgs[0].addr = address;
			msgs[0].flags = I2C_M_TEN;
			msgs[0].len = offset_width;
			msgs[0].buf = offset;

			msgs[1].addr = address;
			msgs[1].flags = I2C_M_TEN | I2C_M_STOP | I2C_M_RD;
			msgs[1].len = size;
			msgs[1].buf = data;

			rdwr.nmsgs = 2;
			rdwr.msgs = msgs;
		} else {
			ioctl(fd, I2C_SLAVE, address);
			rc = read(fd, data, size);
			if (rc < 0) {
				printf("failed to write offset and read: %s\n",
				       strerror(errno));
				goto done;
			}

			printf("read %ld bytes from 0x%02X:\n", size, address);
			display_buf(data, size);
			rc = 0;
			goto done;
		}

		rc = ioctl(fd, I2C_RDWR, &rdwr);
		if (rc < 0) {
			printf("failed to write offset and read: %s\n",
			       strerror(errno));
			if (fmsgs)
				free(fmsgs);
			goto done;
		}

		printf("read %ld bytes from 0x%02X, offset 0x", size, address);
		for (i = 0; i < offset_width; ++i)
			printf("%02X", rdwr.msgs[0].buf[i]);
		printf(":\n");
		display_buf(data, size);
		if (fmsgs)
			free(fmsgs);
	}
		break;
	case WRITE:
		ioctl(fd, I2C_SLAVE, address);
		rc = write(fd, data, size + offset_width);
		if (rc < 0) {
			printf("failed to write: %s\n", strerror(errno));
			goto done;
		}

		printf("wrote %ld bytes to 0x%02X", size, address);
		if (offset_width) {
			int i;

			printf(", offset 0x");
			for (i = 0; i < offset_width; ++i)
				printf("%02X", data[i]);
		}
		printf(":\n");
		display_buf(data + offset_width, size);
		rc = 0;
		break;
	case SCAN:
	{
		unsigned int i, found = 0;
		unsigned char sdata;
		unsigned char found_list[128];

		for (i = 0; i < 256; i += 2) {
			ioctl(fd, I2C_SLAVE, i);
			rc = read(fd, &sdata, 1);
			if (rc == 1)
				found_list[found++] = i;
		}

		printf("found %d devices:\n", found);
		display_buf(found_list, found);
	}
		break;
	default:
		printf("unknown command\n");
		rc = -1;
	}

done:
	free(data);

free:
	if (arg_data)
		free(arg_data);

close:
	close(fd);

	return rc;	
}

int do_write_sbe(int fd, const char *buf, size_t len)
{
	int rc;
	size_t total = 0;

	do {
		rc = write(fd, &buf[total], len - total);
		if (rc < 0)
			return rc;
		else if (!rc)
			break;

		total += rc;
	} while (total < len);

	return (total == len) ? 0 : -EMSGSIZE;
}

int do_read_sbe(int fd, char *buf, size_t len)
{
	int rc;
	size_t total = 0;

	do {
		rc = read(fd, &buf[total], len - total);
		if (rc < 0)
			return rc;
		else if (!rc)
			break;

		total += rc;
	} while (total < len);

	return (total == len) ? 0 : -EMSGSIZE;
}

int do_putscom(int fd, uint64_t addr, uint64_t data, char verbose)
{
	int rc;
	uint32_t buf[6];

	buf[0] = htobe32(0x6);
	buf[1] = htobe32(0xa202);
	buf[2] = htobe32((uint32_t)(addr >> 32));
	buf[3] = htobe32((uint32_t)(addr & 0xFFFFFFFFULL));
	buf[4] = htobe32((uint32_t)(data >> 32));
	buf[5] = htobe32((uint32_t)(data & 0xFFFFFFFFULL));

	if (verbose) {
		printf("putscom buffer:\n");
		display_buf((uint8_t *)buf, sizeof(buf));
	}

	rc = do_write_sbe(fd, (const char *)buf, sizeof(buf));
	if (rc) {
		printf("failed to write putscom to %016llX: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		return rc;
	}

	rc = do_read_sbe(fd, (char *)buf, 8);
	if (rc) {
		printf("failed to read putscom to %016llX response: %s\n",
		       addr, errno ? strerror(errno) : strerror(rc));
		return rc;
	}

	buf[2] = be32toh(buf[0]);
	buf[3] = be32toh(buf[1]);

	if ((buf[2] != 0xC0DEA202) || (buf[3] & 0x0FFFFFFF)) {
		printf("bad response from SBE: %08X %08X\n", buf[2], buf[3]);
		return -EFAULT;
	}

	return 0;
}

int do_getscom(int fd, uint64_t addr, uint64_t *data, char verbose)
{
	int rc;
	uint32_t resp[2];
	uint32_t buf[4];

	buf[0] = htobe32(0x4);
	buf[1] = htobe32(0xa201);
	buf[2] = htobe32((uint32_t)(addr >> 32));
	buf[3] = htobe32((uint32_t)(addr & 0xFFFFFFFFULL));

	if (verbose) {
		printf("getscom buffer:\n");
		display_buf((uint8_t *)buf, sizeof(buf));
	}

	rc = do_write_sbe(fd, (const char *)buf, sizeof(buf));
	if (rc) {
		printf("failed to write getscom from %016llX: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		return rc;
	}

	rc = do_read_sbe(fd, (char *)buf, sizeof(buf));
	if (rc) {
		printf("failed to read getscom from %016llX response: %s\n",
		       addr, errno ? strerror(errno) : strerror(rc));
		return rc;
	}

	resp[0] = be32toh(buf[2]);
	resp[1] = be32toh(buf[3]);

	if ((resp[0] != 0xC0DEA201) || (resp[1] & 0x0FFFFFFF)) {
		printf("bad response from SBE: %08X %08X\n", resp[0], resp[1]);
		return -EFAULT;
	}

	*data = 0ULL;
	*data |= (uint64_t)(be32toh(buf[0])) << 32;
	*data |= (be32toh(buf[1]));

	return 0;
}

int do_putsram(int fd, uint32_t addr, uint8_t *data, size_t len, char verbose)
{
	int rc;
	uint32_t *buf;
	uint32_t data_len = ((len + 7) / 8) * 8;
	size_t cmd_len = data_len + 20;

	buf = malloc(cmd_len);
	if (!buf)
		return -ENOMEM;

	memset(&buf[5], 0, data_len);

	buf[0] = htobe32(0x5 + (data_len / 4));
	buf[1] = htobe32(0xa404);
	buf[2] = htobe32(1);
	buf[3] = htobe32(addr);
	buf[4] = htobe32(data_len);

	memcpy(&buf[5], data, len);

	if (verbose) {
		printf("putsram buffer:\n");
		display_buf((uint8_t *)buf, cmd_len);
	}

	rc = do_write_sbe(fd, (const char *)buf, cmd_len);
	if (rc) {
		printf("failed to write putsram to %08X: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		goto done;
	}

	rc = do_read_sbe(fd, (char *)buf, 12);
	if (rc) {
		printf("failed to read putsram to %08X response: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		goto done;
	}

	buf[3] = be32toh(buf[0]);
	buf[4] = be32toh(buf[1]);
	buf[5] = be32toh(buf[2]);

	if ((buf[3] != data_len) || (buf[4] != 0xC0DEA404) ||
	    (buf[5] & 0x0FFFFFFF)) {
		printf("bad response from SBE %08X %08X %08x\n", buf[3],
		       buf[4], buf[5]);
		rc = -EFAULT;
		goto done;
	}

	rc = 0;

done:
	free(buf);

	return rc;
}

int do_getsram(int fd, uint32_t addr, uint8_t *data, size_t len, char verbose)
{
	int rc;
	uint8_t *resp;
	uint32_t resp_len;
	uint32_t buf[5];
	uint32_t data_len = ((len + 7) / 8) * 8;

	buf[0] = htobe32(0x5);
	buf[1] = htobe32(0xa403);
	buf[2] = htobe32(1);
	buf[3] = htobe32(addr);
	buf[4] = htobe32(data_len);

	resp = malloc(data_len);
	if (!resp)
		return -ENOMEM;

	if (verbose) {
		printf("getsram buffer:\n");
		display_buf((uint8_t *)buf, sizeof(buf));
	}

	rc = do_write_sbe(fd, (const char *)buf, sizeof(buf));
	if (rc) {
		printf("failed to write getsram from %08X: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		goto done;
	}

	rc = do_read_sbe(fd, (char *)resp, data_len);
	if (rc) {
		printf("failed to read getsram from %08X response: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		goto done;
	}

	rc = do_read_sbe(fd, (char *)buf, 16);
	if (rc) {
		printf("failed to read getsram from %08X response: %s\n", addr,
		       errno ? strerror(errno) : strerror(rc));
		goto done;
	}

	if (verbose) {
		printf("getsram return:\n");
		display_buf((uint8_t *)buf, 16);
	}

	resp_len = be32toh(buf[0]);
	buf[3] = be32toh(buf[1]);
	buf[4] = be32toh(buf[2]);

	if ((resp_len != data_len) || (buf[3] != 0xC0DEA403) ||
	    (buf[4] & 0x0FFFFFFF)) {
		printf("bad response from SBE %08X %08X %08x\n", resp_len,
		       buf[3], buf[4]);
		rc = -EFAULT;
		goto done;
	}

	memcpy(data, resp, len);
	rc = 0;

done:
	free(resp);

	return rc;
}

const char *sbefifo_help =
	"fsidbg SBE FIFO device:\n"
	"-p --putscom <x>		putscom to address x\n"
	"-g --getscom <x>		getscom from address x\n"
	"--putsram <x>			putsram to address x\n"
	"--getsram <x>			getsram from address x\n"
	"-d --data x			specify data for puts, in hex bytes\n"
	"-s --size <x>			specify size for sram ops\n"
	"-v --verbose			additional debug info\n"
	"Example:\n"
	"    fsidbg /dev/sbefifo1 --getscom 0x6D051\n"
	"        Fetches 8 bytes from 0x6D051\n"
	"    fsidbg /dev/sbefifo1 --putsram 0xFFFBE000 -d 0100000120002200\n"
	"        Writes a poll command to SRAM\n";

int do_sbefifo(int argc, char **argv, char *dev)
{
	enum command_type {
		PUTSCOM,
		GETSCOM,
		PUTSRAM,
		GETSRAM,
		NUM_COMMAND_TYPES
	};

	char verbose = 0, set_data = 0;
	int fd, rc = 0, cmd = -1, option;
	uint8_t *data = NULL;
	unsigned long address_sram = 0;
	unsigned long size = 0;
	uint64_t address_scom = 0;
	uint64_t data_scom = 0;
	char *arg_data = NULL;
	const char *opts = "p:g:d:s:hv";
	struct option lopts[] = {
		{ "putscom", 1, 0, 'p' },
		{ "getscom", 1, 0, 'g' },
		{ "putsram", 1, 0, PUTSRAM },
		{ "getsram", 1, 0, GETSRAM },
		{ "data", 1, 0, 'd' },
		{ "size", 1, 0, 's' },
		{ "help", 0, 0, 'h' },
		{ "verbose", 0, 0, 'v' },
		{ 0, 0, 0, 0 }
	};

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("couldn't open device %s: %s\n", dev, strerror(errno));
		return -ENODEV;
	}

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			cmd = PUTSCOM;
			if ((rc = arg_to_uint64(optarg, &address_scom)))
				goto free;
			break;
		case 'g':
			cmd = GETSCOM;
			if ((rc = arg_to_uint64(optarg, &address_scom)))
				goto free;
			break;
		case PUTSRAM:
			cmd = PUTSRAM;
			if ((rc = arg_to_uint(optarg, &address_sram)))
				goto free;
			break;
		case GETSRAM:
			cmd = GETSRAM;
			if ((rc = arg_to_uint(optarg, &address_sram)))
				goto free;
			break;
		case 'd':
			set_data = 1;

			arg_to_uint64(optarg, &data_scom);

			arg_data = malloc(strlen(optarg) + 1);
			if (!arg_data) {
				rc = -ENOMEM;
				goto close;
			}

			strcpy(arg_data, optarg);
			break;
		case 's':
			if ((rc = arg_to_uint(optarg, &size)))
				goto free;

			if (!size) {
				printf("bad size\n");
				rc = -1;
				goto free;
			}
			break;
		case 'h':
			printf("%s", sbefifo_help);
			goto free;
		case 'v':
			verbose = 1;
			break;
		default:
			printf("unknown option %c\n", option);
		}
	}

	if (size) {
		data = malloc(size);
		if (!data) {
			rc = -ENOMEM;
			goto free;
		}
	}

	if (cmd == PUTSRAM && arg_data)
		get_data(data, size, arg_data);

	switch (cmd) {
	case PUTSCOM:
		if (!set_data) {
			printf("attempted write without data; abort\n");
			goto done;
		}

		rc = do_putscom(fd, address_scom, data_scom, verbose);
		if (rc)
			goto done;

		printf("putscom %016llX to %016llX\n", data_scom,
		       address_scom);
		break;
	case GETSCOM:
		rc = do_getscom(fd, address_scom, &data_scom, verbose);
		if (rc)
			goto done;

		printf("%016llX\n", data_scom);
		break;
	case PUTSRAM:
		rc = do_putsram(fd, address_sram, data, size, verbose);
		if (rc)
			goto done;

		printf("putsram %ld bytes to %08lX\n:", size, address_sram);
		display_buf(data, size);
		break;
	case GETSRAM:
		rc = do_getsram(fd, address_sram, data, size, verbose);
		if (rc)
			goto done;

		printf("getsram %ld bytes from %08lX:\n", size, address_sram);
		display_buf(data, size);
		break;
	default:
		printf("unknown command\n");
		rc = -1;
	}

done:
	if (data)
		free(data);

free:
	if (arg_data)
		free(arg_data);

close:
	close(fd);
	
	return rc;
}

const char *occ_help =
	"fsidbg OCC device:\n"
	"-c --cmd <x>			specify command byte\n"
	"-d --data x			specify command data, in hex bytes\n"
	"-s --size <x>			specify command lenth\n"
	"-v --verbose			additional debug info\n"
	"Example:\n"
	"    fsidbg /dev/occ1 -c 0 -s 1 -d 20\n"
	"        Writes a poll command to the OCC sram and reads response.\n";

int do_occ(int argc, char **argv, char *dev)
{
	char verbose = 0;
	int fd, rc = 0, option;
	unsigned long command = 0, data_len = 0, size;
	char *arg_data = NULL;
	uint8_t *data = NULL;
	uint8_t resp[4096];
	const char *opts = "c:d:s:hv";
	struct option lopts[] = {
		{ "cmd", 1, 0, 'c' },
		{ "data", 1, 0, 'd' },
		{ "size", 1, 0, 's' },
		{ "help", 0, 0, 'h' },
		{ "verbose", 0, 0, 'v' },
		{ 0, 0, 0, 0 }
	};

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("couldn't open device %s: %s\n", dev, strerror(errno));
		return -ENODEV;
	}

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'c':
			if ((rc = arg_to_uint(optarg, &command)))
				goto free;
			break;
		case 'd':
			arg_data = malloc(strlen(optarg) + 1);
			if (!arg_data) {
				rc = -ENOMEM;
				goto close;
			}

			strcpy(arg_data, optarg);
			break;
		case 's':
			if ((rc = arg_to_uint(optarg, &data_len)))
				goto free;
			break;
		case 'h':
			printf("%s", occ_help);
			goto free;
		case 'v':
			verbose = 1;
			break;
		default:
			printf("unknown option %c\n", option);
		}
	}

	size = data_len + 3;

	data = malloc(size);
	if (!data) {
		rc = -ENOMEM;
		goto free;
	}

	memset(data, 0, size);

	data[0] = command;
	if (data_len && arg_data) {
		uint16_t data_len_be = htobe16((uint16_t)data_len);

		memcpy(&data[1], &data_len_be, 2);
		get_data(&data[3], data_len, arg_data);
	}

	if (verbose) {
		printf("writing occ command:\n");
		display_buf(data, size);
	}

	rc = write(fd, data, size);
	if (rc < 0) {
		printf("failed to write OCC cmd: %s\n", strerror(errno));
		goto done;
	}

	rc = read(fd, resp, sizeof(resp));
	if (rc < 0) {
		printf("failed to read OCC resp: %s\n", strerror(errno));
		goto done;
	}

	printf("got %d bytes OCC response:\n", rc);
	display_buf(resp, rc);
	
done:
	if (data)
		free(data);
free:
	if (arg_data)
		free(arg_data);
close:
	close(fd);

	return rc;
}

static const do_fsi_op device_type_ops[NUM_DEVICE_TYPES] = {
	do_raw,
	do_scom,
	do_i2c,
	do_sbefifo,
	do_occ,
};

const char *general_help =
	"Usage: fsidbg <device path> [DEVICE SPECIFIC OPTIONS]\n"
	"Example:\n"
	"    fsidbg /dev/scom1 -r 0x6D051\n";

int main(int argc, char **argv)
{
	char dev[64];
	int type;

	if (argc < 2) {
		printf("not enough arguments!\n");
		printf("%s", general_help);
		return -EINVAL;
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		printf("%s", general_help);
		return 0;
	}

	strncpy(dev, argv[1], sizeof(dev));

	type = detect_device_type(dev);
	if (type < 0 || type > NUM_DEVICE_TYPES) {
		printf("invalid device %s\n", dev);
		return -EINVAL;
	}

	return device_type_ops[type](argc, argv, dev);
}
