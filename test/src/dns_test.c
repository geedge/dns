#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <assert.h>

#include <MESA/stream.h>
#include <MESA/dns.h>
#include <MESA/cJSON.h>

#define	LOG_PATH	"./log/dns/"
#define	DEBUG	1

char *DNS_TEST_VERSION_20190717=NULL;

int rr_print(dns_info_t *dns_info, struct streaminfo *a_udp, int thread_seq, void *a_packet, int *dns_sec)
{
	int i = 0, j = 0;
	int used_len = 0, len = 0;
	FILE *fp = NULL;
	char filename[256];
	char dns_header[256];
	char question[1024];
	char rr_buf[4096];
	char ip_str[128];
	char tmp_buf[2048];
	char maps[2048];
	char salt_value[2048];
	dns_rr_t *dns_rr = NULL;
	char *buf = NULL;
	int buflen = sizeof(rr_buf);
	buf = rr_buf;
	cJSON *dns_info_object=cJSON_CreateObject();
	cJSON *dns_hdr_object=cJSON_CreateObject();
	cJSON *dns_flags_object=cJSON_CreateObject();
	cJSON *dns_question_array=cJSON_CreateArray();
	cJSON *dns_rr_array=cJSON_CreateArray();

	memset(filename, 0 , sizeof(filename));
	memset(dns_header, 0 , sizeof(dns_header));
	snprintf(filename, sizeof(filename), "%s%s", (char *)LOG_PATH, printaddr(&a_udp->addr, thread_seq));

	fp = fopen(filename, "a+");
	if(fp == NULL)
	{
		return 0;
	}

	used_len = snprintf(dns_header, sizeof(dns_header), 
						"hdr_info: <id=0X%02x, QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d,Z=%d, RCODE=%d, qdcount=%d, ancount=%d, aucount=%d, adcount=%d>\n",
						dns_info->hdr_info.id,
						dns_info->hdr_info.qr,
						dns_info->hdr_info.opcode,
						dns_info->hdr_info.aa,
						dns_info->hdr_info.tc,
						dns_info->hdr_info.rd,
						dns_info->hdr_info.ra,
						dns_info->hdr_info.z,
						dns_info->hdr_info.rcode,
						dns_info->hdr_info.qdcount,
						dns_info->hdr_info.ancount,
						dns_info->hdr_info.aucount,
						dns_info->hdr_info.adcount);
	
	cJSON_AddNumberToObject(dns_hdr_object, "id", dns_info->hdr_info.id);
	cJSON_AddNumberToObject(dns_hdr_object, "qdcount", dns_info->hdr_info.qdcount);
	cJSON_AddNumberToObject(dns_hdr_object, "ancount", dns_info->hdr_info.ancount);
	cJSON_AddNumberToObject(dns_hdr_object, "aucount", dns_info->hdr_info.aucount);
	cJSON_AddNumberToObject(dns_hdr_object, "adcount", dns_info->hdr_info.adcount);

	cJSON_AddNumberToObject(dns_flags_object, "qr", dns_info->hdr_info.qr);
	cJSON_AddNumberToObject(dns_flags_object, "opcode", dns_info->hdr_info.opcode);
	cJSON_AddNumberToObject(dns_flags_object, "aa", dns_info->hdr_info.aa);
	cJSON_AddNumberToObject(dns_flags_object, "tc", dns_info->hdr_info.tc);
	cJSON_AddNumberToObject(dns_flags_object, "rd", dns_info->hdr_info.rd);
	cJSON_AddNumberToObject(dns_flags_object, "ra", dns_info->hdr_info.ra);
	cJSON_AddNumberToObject(dns_flags_object, "z", dns_info->hdr_info.z);
	cJSON_AddNumberToObject(dns_flags_object, "rcode", dns_info->hdr_info.rcode);

	fwrite(dns_header, used_len, 1, fp);

	cJSON_AddItemToObject(dns_info_object, "hdr", dns_hdr_object);
	cJSON_AddItemToObject(dns_info_object, "flags", dns_flags_object);
	cJSON_AddItemToObject(dns_info_object,"question", dns_question_array);
	for(i = 0; i < dns_info->hdr_info.qdcount && (&dns_info->query_question[i])!=NULL; i++)
	{
		used_len = snprintf(question, sizeof(question), "question: <qtype: %d, qclass: %d, qname: %s>\n",
											 dns_info->query_question[i].qtype,
											 dns_info->query_question[i].qclass,
											 dns_info->query_question[i].qname);
			
		cJSON *dns_question_object=cJSON_CreateObject();
		cJSON_AddItemToArray(dns_question_array, dns_question_object);

		cJSON_AddNumberToObject(dns_question_object, "qtype", dns_info->query_question[i].qtype);
		cJSON_AddNumberToObject(dns_question_object, "qclass", dns_info->query_question[i].qclass);
		cJSON_AddStringToObject(dns_question_object, "qname", (const char *)dns_info->query_question[i].qname);
	}

	fwrite(question, used_len, 1, fp);

	used_len = snprintf(rr_buf, sizeof(rr_buf), "RRS count: %d\n", dns_info->rr_count);
	fwrite(rr_buf, used_len, 1, fp);

	
	cJSON_AddItemToObject(dns_info_object, "rr", dns_rr_array);
	
	for(i = 0; i < dns_info->rr_count; i++)
	{
		cJSON *dns_rr_object=cJSON_CreateObject();
		cJSON_AddItemToArray(dns_rr_array, dns_rr_object);

		used_len = 0;
		dns_rr = &(dns_info->rr[i]);
		memset(rr_buf, 0 , sizeof(rr_buf));

		if(dns_rr->type == DNS_TYPE_OPT)
		{
			used_len += snprintf(rr_buf, sizeof(rr_buf), "RRS%d OPT <name: %s, type: %d, udp_payload: %d, extended RCODE: %d, version: %d, Z; 0X%x, rdlength: %d>\n",
											i,
											dns_rr->name,
											dns_rr->type,
											dns_rr->rr_class,
											dns_rr->ttl>>24,
											(dns_rr->ttl>>16)&0xFF,
											dns_rr->ttl&&0xFFFF,
											dns_rr->rdlength);
			
			cJSON_AddStringToObject(dns_rr_object, "name", (const char *)(dns_rr->name));
			cJSON_AddNumberToObject(dns_rr_object, "type", dns_rr->type);
			cJSON_AddNumberToObject(dns_rr_object, "udp_payload", dns_rr->rr_class);
			cJSON_AddNumberToObject(dns_rr_object, "rcode", (int)(dns_rr->ttl>>24));
			cJSON_AddNumberToObject(dns_rr_object, "version", (int)((dns_rr->ttl>>16)&0xFF));
			cJSON_AddNumberToObject(dns_rr_object, "Z", (int)(dns_rr->ttl&&0xFFFF));
			cJSON_AddNumberToObject(dns_rr_object, "rdlength", dns_rr->rdlength);
		}
		else
		{
			used_len += snprintf(rr_buf, sizeof(rr_buf), "RRS%d <name: %s, type: %d, rr_class: %d, ttl: %d, rdlength: %d>",
											i,
											dns_rr->name,
											dns_rr->type,
											dns_rr->rr_class,
											dns_rr->ttl,
											dns_rr->rdlength);

			cJSON_AddStringToObject(dns_rr_object, "name", (const char *)(dns_rr->name));
			cJSON_AddNumberToObject(dns_rr_object, "type", dns_rr->type);
			cJSON_AddNumberToObject(dns_rr_object, "class", dns_rr->rr_class);
			cJSON_AddNumberToObject(dns_rr_object, "ttl", dns_rr->ttl);
			cJSON_AddNumberToObject(dns_rr_object, "rdlength", dns_rr->rdlength);
		}
	
		switch(dns_rr->type)
		{
			case DNS_TYPE_A:
				inet_ntop(AF_INET, (void *)(dns_rr->rdata.a), ip_str, sizeof(ip_str));
				used_len += snprintf(buf+used_len, buflen-used_len, "[A: %s]\n", ip_str);
				cJSON_AddStringToObject(dns_rr_object, "a", ip_str);
				break;
			case DNS_TYPE_NS:
				used_len += snprintf(buf+used_len, buflen-used_len, "[NS: %s]\n", dns_rr->rdata.ns);
				cJSON_AddStringToObject(dns_rr_object, "ns", (const char *)(dns_rr->rdata.ns));
				break;
			case DNS_TYPE_MD:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MD: %s]\n", dns_rr->rdata.md);
				cJSON_AddStringToObject(dns_rr_object, "md", (const char *)(dns_rr->rdata.md));
				break;
			case DNS_TYPE_MF:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MF: %s]\n", dns_rr->rdata.mf);
				cJSON_AddStringToObject(dns_rr_object, "mf", (const char *)(dns_rr->rdata.mf));
				break;
			case DNS_TYPE_CNAME:
				used_len += snprintf(buf+used_len, buflen-used_len, "[CNAME: %s]\n", dns_rr->rdata.cname);
				cJSON_AddStringToObject(dns_rr_object, "cname", (const char *)(dns_rr->rdata.cname));
				break;
			case DNS_TYPE_SOA:
				used_len += snprintf(buf+used_len, buflen-used_len, 
							"[SOA  mname: %s, rname: %s, serial: %u, refresh: %u, retry: %u, expire: %u, minimum: %u]\n",
							dns_rr->rdata.soa->mname,
							dns_rr->rdata.soa->rname,
							dns_rr->rdata.soa->serial,
							dns_rr->rdata.soa->refresh,
							dns_rr->rdata.soa->retry,
							dns_rr->rdata.soa->expire,
							dns_rr->rdata.soa->minimum);
				cJSON_AddStringToObject(dns_rr_object, "mname", (const char *)(dns_rr->rdata.soa->mname));
				cJSON_AddStringToObject(dns_rr_object, "rname", (const char *)(dns_rr->rdata.soa->rname));
				cJSON_AddNumberToObject(dns_rr_object, "serial", dns_rr->rdata.soa->serial);
				cJSON_AddNumberToObject(dns_rr_object, "refresh", dns_rr->rdata.soa->refresh);
				cJSON_AddNumberToObject(dns_rr_object, "retry", dns_rr->rdata.soa->retry);
				cJSON_AddNumberToObject(dns_rr_object, "cname", dns_rr->rdata.soa->expire);
				cJSON_AddNumberToObject(dns_rr_object, "minimum", dns_rr->rdata.soa->minimum);
				break;
			case DNS_TYPE_MB:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MB: %s]\n", dns_rr->rdata.mb);
				cJSON_AddStringToObject(dns_rr_object, "mb", (const char *)(dns_rr->rdata.mb));
				break;
			case DNS_TYPE_MG:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MG: %s]\n", dns_rr->rdata.mg);
				cJSON_AddStringToObject(dns_rr_object, "mg", (const char *)(dns_rr->rdata.mg));
				break;
			case DNS_TYPE_MR:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MR: %s]\n", dns_rr->rdata.mr);
				cJSON_AddStringToObject(dns_rr_object, "mr", (const char *)(dns_rr->rdata.mr));
				break;
			case DNS_TYPE_NULL:
				used_len += snprintf(buf+used_len, buflen-used_len, "[null size: %u, null: %s]\n",
													dns_rr->rdata.null->size, dns_rr->rdata.null->null);
				cJSON_AddNumberToObject(dns_rr_object, "size", dns_rr->rdata.null->size);
				cJSON_AddStringToObject(dns_rr_object, "null", (const char *)(dns_rr->rdata.null->null));
				break;
			case DNS_TYPE_WKS:
				inet_ntop(AF_INET, &(dns_rr->rdata.wks->addr), ip_str, sizeof(ip_str));
				used_len += snprintf(buf+used_len, buflen-used_len, "[WKS addr: %s, protocol: %u, bitmap: %s, size: %u]\n",
									ip_str, dns_rr->rdata.wks->protocol, dns_rr->rdata.wks->bitmap, dns_rr->rdata.wks->size);
				
				cJSON_AddStringToObject(dns_rr_object, "addr", ip_str);
				cJSON_AddNumberToObject(dns_rr_object, "protocol", dns_rr->rdata.wks->protocol);
				cJSON_AddStringToObject(dns_rr_object, "bitmap", (const char *)(dns_rr->rdata.wks->bitmap));
				cJSON_AddNumberToObject(dns_rr_object, "size", dns_rr->rdata.wks->size);
				break;
			case DNS_TYPE_PTR:
				used_len += snprintf(buf+used_len, buflen-used_len, "[PTR: %s]\n", dns_rr->rdata.ptr);
				cJSON_AddStringToObject(dns_rr_object, "ptr", (const char *)(dns_rr->rdata.ptr));
				break;
			case DNS_TYPE_HINFO:
				used_len += snprintf(buf+used_len, buflen-used_len, "[HINFO cpu: %s, os: %s]\n", 
								dns_rr->rdata.hinfo->cpu, dns_rr->rdata.hinfo->os);
				
				cJSON_AddStringToObject(dns_rr_object, "cpu", (const char *)(dns_rr->rdata.hinfo->cpu));
				cJSON_AddStringToObject(dns_rr_object, "os", (const char *)(dns_rr->rdata.hinfo->os));
				break;
			case DNS_TYPE_MINFO:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MINFO rmailbx: %s, emailbx: %s]\n",
								dns_rr->rdata.minfo->rmailbx, dns_rr->rdata.minfo->emailbx);

				cJSON_AddStringToObject(dns_rr_object, "rmailbx", (const char *)(dns_rr->rdata.minfo->rmailbx));
				cJSON_AddStringToObject(dns_rr_object, "emailbx", (const char *)(dns_rr->rdata.minfo->emailbx));
				break;
			case DNS_TYPE_MX:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MX preference: %u, exchange: %s]\n",
								dns_rr->rdata.mx->preference, dns_rr->rdata.mx->exchange);

				cJSON_AddStringToObject(dns_rr_object, "exchange", (const char *)(dns_rr->rdata.mx->exchange));
				cJSON_AddNumberToObject(dns_rr_object, "preference", dns_rr->rdata.mx->preference);
				break;
			case DNS_TYPE_TXT:
				used_len += snprintf(buf+used_len, buflen-used_len, "[TXT size: %u, txt: %s]\n",
								dns_rr->rdata.txt->size, dns_rr->rdata.txt->txt);

				cJSON_AddStringToObject(dns_rr_object, "txt", (const char *)(dns_rr->rdata.txt->txt));
				cJSON_AddNumberToObject(dns_rr_object, "size", dns_rr->rdata.txt->size);
				break;
			case DNS_TYPE_RP:
				used_len += snprintf(buf+used_len, buflen-used_len, "[mailbox: %s, txt_rr: %s]\n",
								dns_rr->rdata.rp->mailbox, dns_rr->rdata.rp->txt_rr);

				cJSON_AddStringToObject(dns_rr_object, "mailbox", (const char *)(dns_rr->rdata.rp->mailbox));
				cJSON_AddStringToObject(dns_rr_object, "txt_rr", (const char *)(dns_rr->rdata.rp->txt_rr));
				break;
			case DNS_TYPE_AAAA:
				inet_ntop(AF_INET6, dns_rr->rdata.aaaa, ip_str, sizeof(ip_str));
				used_len += snprintf(buf+used_len, buflen-used_len, "[AAAA: %s]\n", ip_str);
				cJSON_AddStringToObject(dns_rr_object, "aaaa", ip_str);
				break;
			case DNS_TYPE_OPT:
				break;
			case DNS_TYPE_DS:
				*dns_sec = 2;
				len = 0;
				assert(dns_rr->rdata.ds->digest_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.ds->digest_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.ds->digest[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len,
									"[DS key_tag: %u, algo: %u, digest_type: %u, digest: %s]\n",
										dns_rr->rdata.ds->key_tag, dns_rr->rdata.ds->algo,
										dns_rr->rdata.ds->digest_type, tmp_buf);

				cJSON_AddNumberToObject(dns_rr_object, "key_tag", dns_rr->rdata.ds->key_tag);
				cJSON_AddNumberToObject(dns_rr_object, "algo", dns_rr->rdata.ds->algo);
				cJSON_AddNumberToObject(dns_rr_object, "digest_type", dns_rr->rdata.ds->digest_type);
				cJSON_AddStringToObject(dns_rr_object, "digest", tmp_buf);
				break;
			case DNS_TYPE_RRSIG:
				*dns_sec = 2;
				len = 0;
				assert(dns_rr->rdata.rrsig->signature_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.rrsig->signature_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.rrsig->signature[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len,
									"[RRSIG type_covered: %u, algo: %u, labels: %u, original_ttl: %u, sig_expiration: %u, sig_inception: %u, key_tag: %u, signer_name: %s, signature: %s]\n",
										dns_rr->rdata.rrsig->type_covered, dns_rr->rdata.rrsig->algo,
										dns_rr->rdata.rrsig->labels, dns_rr->rdata.rrsig->original_ttl,
										dns_rr->rdata.rrsig->sig_expiration, dns_rr->rdata.rrsig->sig_inception,
										dns_rr->rdata.rrsig->key_tag, dns_rr->rdata.rrsig->signer_name, tmp_buf);

				cJSON_AddNumberToObject(dns_rr_object, "type_covered", dns_rr->rdata.rrsig->type_covered);
				cJSON_AddNumberToObject(dns_rr_object, "algo", dns_rr->rdata.rrsig->algo);
				cJSON_AddNumberToObject(dns_rr_object, "labels", dns_rr->rdata.rrsig->labels);
				cJSON_AddNumberToObject(dns_rr_object, "original_ttl", dns_rr->rdata.rrsig->original_ttl);
				cJSON_AddNumberToObject(dns_rr_object, "sig_expiration", dns_rr->rdata.rrsig->sig_expiration);
				cJSON_AddNumberToObject(dns_rr_object, "sig_inception", dns_rr->rdata.rrsig->sig_inception);
				cJSON_AddNumberToObject(dns_rr_object, "key_tag", dns_rr->rdata.rrsig->key_tag);
				cJSON_AddStringToObject(dns_rr_object, "signer_name", (const char *)(dns_rr->rdata.rrsig->signer_name));
				cJSON_AddStringToObject(dns_rr_object, "signature", tmp_buf);
				break;
			case DNS_TYPE_NSEC:
				*dns_sec = 2;
				len = 0;
				for(j = 0; j < (int)(dns_rr->rdata.nsec->maps_len); j++)
				{
					len += snprintf(maps+len, sizeof(maps)-len, "%02x", dns_rr->rdata.nsec->type_bit_maps[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len, "[NSEC next_domain: %s, type_bit_maps: %s]\n", dns_rr->rdata.nsec->next_domain, maps);

				cJSON_AddStringToObject(dns_rr_object, "next_domain", (const char *)(dns_rr->rdata.nsec->next_domain));
				cJSON_AddStringToObject(dns_rr_object, "type_bit_maps", maps);
				break;
			case DNS_TYPE_DNSKEY:
				*dns_sec = 2;
				len = 0;
				assert(dns_rr->rdata.dnskey->public_key_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.dnskey->public_key_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.dnskey->public_key[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len, "[DNSKEY flags: %u, protocol: %u, algo: %u, public_key: %s]\n",
							dns_rr->rdata.dnskey->flags, dns_rr->rdata.dnskey->protocol, dns_rr->rdata.dnskey->algo, tmp_buf);

				cJSON_AddNumberToObject(dns_rr_object, "flags", dns_rr->rdata.dnskey->flags);
				cJSON_AddNumberToObject(dns_rr_object, "protocol", dns_rr->rdata.dnskey->protocol);
				cJSON_AddNumberToObject(dns_rr_object, "algo", dns_rr->rdata.dnskey->algo);
				cJSON_AddStringToObject(dns_rr_object, "public_key", tmp_buf);
				break;
			case DNS_TYPE_NSEC3:
				*dns_sec = 2;
				memset(tmp_buf, 0, sizeof(tmp_buf));
				memset(maps, 0, sizeof(maps));
				len = 0;
				assert(dns_rr->rdata.nsec3->hash_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.nsec3->hash_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.nsec3->next_hash_owner[j]);
				}
				len = 0;
				for(j = 0; j < (int)(dns_rr->rdata.nsec3->maps_len); j++)
				{
					len += snprintf(maps+len, sizeof(maps)-len, "%02x", dns_rr->rdata.nsec3->type_bit_maps[j]);
				}
				len = 0;
				for(j = 0; j < (int)(dns_rr->rdata.nsec3->salt_len); j++)
				{
					len += snprintf(salt_value+len, sizeof(salt_value)-len, "%02x", dns_rr->rdata.nsec3->salt_value[j]);
				}
				
				used_len += snprintf(buf+used_len, buflen-used_len,
								"[NSEC3 hash_algo: %u, flags: %u, iteration: %u, salt_len: %u, hash_len: %u, salt_value: %s, next_hash_owner: %s, type_bit_maps: %s]\n",
										dns_rr->rdata.nsec3->hash_algo, dns_rr->rdata.nsec3->flags, 
										dns_rr->rdata.nsec3->iteration, dns_rr->rdata.nsec3->salt_len, 
										dns_rr->rdata.nsec3->hash_len, salt_value, tmp_buf, maps);

				cJSON_AddNumberToObject(dns_rr_object, "hash_algo", dns_rr->rdata.nsec3->hash_algo);
				cJSON_AddNumberToObject(dns_rr_object, "flags", dns_rr->rdata.nsec3->flags);
				cJSON_AddNumberToObject(dns_rr_object, "iteration", dns_rr->rdata.nsec3->iteration);
				cJSON_AddNumberToObject(dns_rr_object, "salt_len", dns_rr->rdata.nsec3->salt_len);
				cJSON_AddNumberToObject(dns_rr_object, "hash_len", dns_rr->rdata.nsec3->hash_len);
				cJSON_AddStringToObject(dns_rr_object, "salt_value", salt_value);
				cJSON_AddStringToObject(dns_rr_object, "next_hash_owner", tmp_buf);
				cJSON_AddStringToObject(dns_rr_object, "type_bit_maps", maps);
				break;
			case DNS_TYPE_NSEC3PARAM:
				len = 0;
				assert(dns_rr->rdata.nsec3param->salt_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.nsec3param->salt_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.nsec3param->salt_value[j]);
				}
				
				used_len += snprintf(buf+used_len, buflen-used_len,
								"[NSEC3PARAM hash_algo: %u, flags: %u, iteration: %u, salt_len: %u, salt_value: %s]\n",
										dns_rr->rdata.nsec3param->hash_algo, dns_rr->rdata.nsec3param->flags,
										dns_rr->rdata.nsec3param->iteration, dns_rr->rdata.nsec3param->salt_len,
										tmp_buf);

				cJSON_AddNumberToObject(dns_rr_object, "hash_algo", dns_rr->rdata.nsec3param->hash_algo);
				cJSON_AddNumberToObject(dns_rr_object, "flags", dns_rr->rdata.nsec3param->flags);
				cJSON_AddNumberToObject(dns_rr_object, "iteration", dns_rr->rdata.nsec3param->iteration);
				cJSON_AddNumberToObject(dns_rr_object, "salt_len", dns_rr->rdata.nsec3param->salt_len);
				cJSON_AddStringToObject(dns_rr_object, "salt_value", tmp_buf);
				break;
			case DNS_TYPE_UNKNOWN:
				used_len += snprintf(buf+used_len, buflen-used_len, "[data: %s]\n", dns_rr->rdata.unknown_data);
				cJSON_AddStringToObject(dns_rr_object, "data", (const char *)(dns_rr->rdata.unknown_data));
				break;
			case DNS_QTYPE_AXFR:
				continue;
				break;
			case DNS_QTYPE_MAILB:
				continue;
				break;
			case DNS_QTYPE_MAILA:
				continue;
				break;
			case DNS_QTYPE_ANY:
				continue;
				break;
			default:
				continue;
				break;
		}
		fwrite(buf, used_len, 1, fp);
	}

	fclose(fp);
	fp = NULL;


	//char *question_array=cJSON_Print(dns_info_object);
	//char *rr_array=cJSON_Print(dns_info_object);

	//cJSON_AddArrayToObject(dns_info_object, question_array);
	//cJSON_AddArrayToObject(dns_info_object, rr_array);

	char *outout1=cJSON_PrintUnformatted(dns_info_object);
	char *outout2=cJSON_Print(dns_info_object);

	printf("%s\n", outout1);
	printf("%s\n", outout2);
	return 0;
}

char dns_test_entry (stSessionInfo *session_info,  void **pme, int thread_seq, struct streaminfo *a_udp, void *a_packet)
{
	int dns_sec = 0;
	dns_info_t *dns_info = (dns_info_t *)session_info->app_info;

	if(dns_info!= NULL)
	{
		#ifdef	DEBUG
		rr_print(dns_info, a_udp, thread_seq, a_packet, &dns_sec);
		#endif
	}

	return PROT_STATE_GIVEME;
}


char dns_build_cheat_pkt_entry (stSessionInfo *session_info,  void **pme, int thread_seq, struct streaminfo *a_udp, void *a_packet)
{
	unsigned char payload[4096] = {0};
	int payload_len = sizeof(payload);
	cheat_pkt_opt_t cheat_opt;
	int cheat_opt_num = 0;
	unsigned char senddir = 0;
	char *cheat_ipv6 = "11:22:33:44:55::66";

	dns_hdr_t *dns_hdr = NULL;


	
	dns_info_t *dns_info = (dns_info_t *)session_info->app_info;

	memset(payload, 0, payload_len);
	dns_hdr = (dns_hdr_t *)payload;

	if(dns_info!= NULL)
	{
		switch(dns_info->query_question->qtype)
		{
			case DNS_TYPE_A:
				cheat_opt.res_type = DNS_TYPE_A;
				cheat_opt.res_len = 4;
				*(unsigned int *)cheat_opt.res_info = 3825598474;
				cheat_opt_num = 1;
				dns_hdr->ancount = 1;
				dns_hdr->id = dns_info->hdr_info.id;
				dns_hdr->qdcount = 1;
				break;
			case DNS_TYPE_AAAA:
				cheat_opt.res_type = DNS_TYPE_AAAA;
				cheat_opt.res_len = 16;
				inet_pton(AF_INET6, cheat_ipv6, cheat_opt.res_info);
				cheat_opt_num = 1;
				dns_hdr->ancount = 1;
				dns_hdr->id = dns_info->hdr_info.id;
				dns_hdr->qdcount = 1;
				break;
		}
		payload_len = build_cheat_pkt(payload, payload_len, dns_info->query_question, &cheat_opt, cheat_opt_num);
		senddir = (a_udp->routedir)^1;
		MESA_inject_pkt(a_udp, (const char *)payload, payload_len, (const char *)a_packet, senddir);
	}

	return PROT_STATE_DROPME;
}

int dns_test_init()
{

	return 0;		
}

void  dns_test_destory()
{
	
}

