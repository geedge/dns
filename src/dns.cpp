/*
 *Author      	  ljp
 *V1.01 2015-01-05  修改头文件，包含最新的stream.h
 *V1.02 2015-01-16  修改dns_compress_domain函数while循环条件，由\0改为\n
 *                  添加对TCP DNS查询的支持
 *V1.03 2015-01-26  cheat pkt TTL set 0.5->1hour
 *V1.04 2015-02-05  修改DNS构造数据包BUG
 *V1.05 2015-02-12  build_dns_payload中添加对AAAA类型应答的支持
 *V1.06 2015-03-05  修复解析TCP DNS时parse_dns中msg赋值小BUG
 *V1.07 2015-03-16  修复A/AAAA应答包域名信息BUG
 *V1.08 2015-05-07  修复au/ad应答包域名信息BUG
 *V1.09 2015-07-15  修复qtype和qclass两种类型未转换成网络序错误

 --------------------------------------------------------------------------
 *2015-09-07, LiJia, 修改注册获取flag_id BUG.
 *2015-09-29, LiJia, 修改TCP协议, 没有跳过长度字段BUG.
 *2015-10-10, LiJia, 修改FLAG_CHANGE()函数没有copy字符串最后EOF的BUG.
 *2016-09-03, liuxueli, 修改代码格式
*/
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>
#include <MESA/stream.h>
#include <MESA/field_stat2.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>
#include "dns.h"
#include "dns_internal.h"

int DNS_PROTOCOL_VERSION_20190419;
unsigned long long dns_register_flag = 0;
unsigned short dns_plugid = 0;
static pthread_mutex_t dns_lock;
int dns_register_flag_num = 0;
int pcap_index = 0;

const char *dns_conf_file = "./conf/dns/dns.conf";
g_dns_proto_info_t g_dns_proto_info;

static dns_str_contrast_id_t DNS_FLAG_ID[] = 
{
	{"DNS_ALL",				DNS_ALL},
	{"DNS_REQ_ALL",			DNS_REQ_ALL},
	{"DNS_RES_ALL",			DNS_RES_ALL},
	{"DNS_REQ_HDR",			DNS_REQ_HDR},
	{"DNS_RES_HDR",			DNS_RES_HDR},
	{"DNS_RES_QUERY",		DNS_RES_QUERY},
	{"DNS_RES_RRS",			DNS_RES_RRS},
	{"DNS_RES_ANSWER",		DNS_RES_ANSWER},
	{"DNS_RES_AUTH",		DNS_RES_AUTH},
	{"DNS_RES_ADD",			DNS_RES_ADD}
};

static dns_str_contrast_id_t DNS_STATIS_INFO[] = 
{
	{"V4_T_PPS",		V4_T_PPS},
	{"V4_T_BPS",		V4_T_BPS},
	{"V4_U_PPS",		V4_U_PPS},
	{"V4_U_BPS",		V4_U_BPS},
	{"V6_T_PPS",		V6_T_PPS},
	{"V6_T_BPS",		V6_T_BPS},
	{"V6_U_PPS",		V6_U_PPS},
	{"V6_U_BPS",		V6_U_BPS},
	{"PKT_UNKNOWN",		PKT_UNKNOWN},
	{"Q_PKT",			Q_PKT},
	{"R_PKT", 			R_PKT},
	{"ERR_PKT",			ERR_PKT},
	{"Q_A",				Q_A},
	{"Q_AAAA",			Q_AAAA},
	{"Q_CNAME",			Q_CNAME},
	{"Q_QUESTION0",		Q_QUESTION},
	{"Q_UNKNOWN",		Q_UNKNOWN}
};


const unsigned char PCAP_FILE_HEAD[24] = {0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};


int get_rr_content2buf(dns_rr_t *rr, int rr_count, char *rr_buf, int buflen, int *dns_sec)
{
	int i = 0, j = 0;
	int len = 0, used_len = 0;
	char ip_str[128];
	char tmp_buf[2048];
	char maps[2048];
	char salt_value[2048];
	char *buf = NULL;
	FILE *fp = NULL;
	dns_rr_t *dns_rr = NULL;

	buf = (char *)calloc(1, buflen+1024);
	
	for(i = 0; i < rr_count; i++)
	{
		len = 0;
		dns_rr = &rr[i];

		if(dns_rr->type == DNS_TYPE_OPT)
		{
			used_len += snprintf(buf+used_len, buflen-used_len, 
									"{RRS%d OPT <name: %s, type: %u, udp_payload: %u, extended RCODE: %u, version: %u, Z; 0X%x, rdlength: %u>};",
									i,
									dns_rr->name,
									dns_rr->type,
									dns_rr->rr_class,
									dns_rr->ttl >> 24,
									(dns_rr->ttl>>16)&0xFF,
									dns_rr->ttl&0xFFFF,
									dns_rr->rdlength);
		}
		else
		{
			used_len += snprintf(buf+used_len, buflen-used_len, "{RRS%d <name: %s, type: %u, rr_class: %u, ttl: %u, rdlength: %u>",
											i,
											dns_rr->name,
											dns_rr->type,
											dns_rr->rr_class,
											dns_rr->ttl,
											dns_rr->rdlength);

		}

		if(dns_rr->rdlength == 0)
		{
			continue;
		}
		
		switch(dns_rr->type)
		{
			case DNS_TYPE_A:
				inet_ntop(AF_INET, (void *)(dns_rr->rdata.a), ip_str, sizeof(ip_str));
				used_len += snprintf(buf+used_len, buflen-used_len, "[A: %s]};", ip_str);
				break;
			case DNS_TYPE_NS:
				used_len += snprintf(buf+used_len, buflen-used_len, "[NS: %s]};", dns_rr->rdata.ns);
				break;
			case DNS_TYPE_MD:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MD: %s]};", dns_rr->rdata.md);
				break;
			case DNS_TYPE_MF:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MF: %s]};", dns_rr->rdata.mf);
				break;
			case DNS_TYPE_CNAME:
				used_len += snprintf(buf+used_len, buflen-used_len, "[CNAME: %s]};", dns_rr->rdata.cname);
				break;
			case DNS_TYPE_SOA:
				used_len += snprintf(buf+used_len, buflen-used_len, 
							"[SOA  mname: %s, rname: %s, serial: %u, refresh: %u, retry: %u, expire: %u, minimum: %u]};",
							dns_rr->rdata.soa->mname,
							dns_rr->rdata.soa->rname,
							dns_rr->rdata.soa->serial,
							dns_rr->rdata.soa->refresh,
							dns_rr->rdata.soa->retry,
							dns_rr->rdata.soa->expire,
							dns_rr->rdata.soa->minimum);
				break;
			case DNS_TYPE_MB:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MB: %s]};", dns_rr->rdata.mb);
				break;
			case DNS_TYPE_MG:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MG: %s]};", dns_rr->rdata.mg);
				break;
			case DNS_TYPE_MR:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MR: %s]};", dns_rr->rdata.mr);
				break;
			case DNS_TYPE_NULL:
				used_len += snprintf(buf+used_len, buflen-used_len, "[null size: %u, null: %s]};",
													dns_rr->rdata.null->size, dns_rr->rdata.null->null);
				break;
			case DNS_TYPE_WKS:
				inet_ntop(AF_INET, &(dns_rr->rdata.wks->addr), ip_str, sizeof(ip_str));
				used_len += snprintf(buf+used_len, buflen-used_len, "[WKS addr: %s, protocol: %u, bitmap: %s, size: %u]};",
									ip_str, dns_rr->rdata.wks->protocol, dns_rr->rdata.wks->bitmap, dns_rr->rdata.wks->size);
				break;
			case DNS_TYPE_PTR:
				used_len += snprintf(buf+used_len, buflen-used_len, "[PTR: %s]};", dns_rr->rdata.ptr);
				break;
			case DNS_TYPE_HINFO:
				used_len += snprintf(buf+used_len, buflen-used_len, "[HINFO cpu: %s, os: %s]};", 
								dns_rr->rdata.hinfo->cpu, dns_rr->rdata.hinfo->os);
				break;
			case DNS_TYPE_MINFO:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MINFO rmailbx: %s, emailbx: %s]};",
								dns_rr->rdata.minfo->rmailbx, dns_rr->rdata.minfo->emailbx);
				break;
			case DNS_TYPE_MX:
				used_len += snprintf(buf+used_len, buflen-used_len, "[MX preference: %u, exchange: %s]};",
								dns_rr->rdata.mx->preference, dns_rr->rdata.mx->exchange);
				break;
			case DNS_TYPE_TXT:
				used_len += snprintf(buf+used_len, buflen-used_len, "[TXT size: %u, txt: %s]};",
								dns_rr->rdata.txt->size, dns_rr->rdata.txt->txt);
				break;
			case DNS_TYPE_AAAA:
				if(dns_rr->rdata.aaaa != NULL)
				{
					inet_ntop(AF_INET6, dns_rr->rdata.aaaa, ip_str, sizeof(ip_str));
					used_len += snprintf(buf+used_len, buflen-used_len, "[AAAA: %s]};", ip_str);
				}
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
									"[DS key_tag: %u, algo: %u, digest_type: %u, digest: %s]};",
										dns_rr->rdata.ds->key_tag, dns_rr->rdata.ds->algo,
										dns_rr->rdata.ds->digest_type, tmp_buf);
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
									"[RRSIG type_covered: %u, algo: %u, labels: %u, original_ttl: %u, sig_expiration: %u, sig_inception: %u, key_tag: %u, signer_name: %s, signature: %s]};",
										dns_rr->rdata.rrsig->type_covered, dns_rr->rdata.rrsig->algo,
										dns_rr->rdata.rrsig->labels, dns_rr->rdata.rrsig->original_ttl,
										dns_rr->rdata.rrsig->sig_expiration, dns_rr->rdata.rrsig->sig_inception,
										dns_rr->rdata.rrsig->key_tag, dns_rr->rdata.rrsig->signer_name, tmp_buf);
				break;
			case DNS_TYPE_NSEC:
				*dns_sec = 2;
				len = 0;
				for(j = 0; j < (int)(dns_rr->rdata.nsec->maps_len); j++)
				{
					len += snprintf(maps+len, sizeof(maps)-len, "%02x", dns_rr->rdata.nsec->type_bit_maps[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len, "[NSEC next_domain: %s, type_bit_maps: %s]};", dns_rr->rdata.nsec->next_domain, maps);
				break;
			case DNS_TYPE_DNSKEY:
				*dns_sec = 2;
				len = 0;
				assert(dns_rr->rdata.dnskey->public_key_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.dnskey->public_key_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.dnskey->public_key[j]);
				}
				used_len += snprintf(buf+used_len, buflen-used_len, "[DNSKEY flags: %u, protocol: %u, algo: %u, public_key: %s]};",
							dns_rr->rdata.dnskey->flags, dns_rr->rdata.dnskey->protocol, dns_rr->rdata.dnskey->algo, tmp_buf);
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
								"[NSEC3 hash_algo: %u, flags: %u, iteration: %u, salt_len: %u, hash_len: %u, salt_value: %s, next_hash_owner: %s, type_bit_maps: %s]};",
										dns_rr->rdata.nsec3->hash_algo, dns_rr->rdata.nsec3->flags, 
										dns_rr->rdata.nsec3->iteration, dns_rr->rdata.nsec3->salt_len, 
										dns_rr->rdata.nsec3->hash_len, salt_value, tmp_buf, maps);
				break;
			case DNS_TYPE_NSEC3PARAM:
				len = 0;
				assert(dns_rr->rdata.nsec3param->salt_len*2<sizeof(tmp_buf));
				for(j = 0; j < (int)(dns_rr->rdata.nsec3param->salt_len); j++)
				{
					len += snprintf(tmp_buf+len, sizeof(tmp_buf)-len, "%02x", dns_rr->rdata.nsec3param->salt_value[j]);
				}
				
				used_len += snprintf(buf+used_len, buflen-used_len,
								"[NSEC3PARAM hash_algo: %u, flags: %u, iteration: %u, salt_len: %u, salt_value: %s]};",
										dns_rr->rdata.nsec3param->hash_algo, dns_rr->rdata.nsec3param->flags,
										dns_rr->rdata.nsec3param->iteration, dns_rr->rdata.nsec3param->salt_len,
										tmp_buf);
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

		if(used_len > buflen-1)
			break;
		
	}
	if(used_len > buflen-1)
	{
		memcpy(rr_buf, buf, buflen);
		rr_buf[buflen-1] = '\0';
		used_len = buflen;
	}
	else
	{
		memcpy(rr_buf, buf, used_len);
		rr_buf[used_len] = '\0';
	}

	if(g_dns_proto_info.log_level < 30)
	{
		fp = fopen("aaaaa", "a+");
		if(fp)
		{
			fwrite(rr_buf, used_len, 1, fp);
			fclose(fp);
			fp = NULL;
		}
	}
	
	free(buf);
	buf = NULL;
	
	return used_len;
}

int dns_save_raw_pkt(char *buf, int buflen, const struct streaminfo * a_stream)
{	
	int min_len = 0, ret = 0;
	void *p_eth_rawpkt = NULL;
	int eth_rawpkt_len = 0;
	struct timeval t;
	pcap_hdr_t pcap_hdr;
	int used_len = 0;
	raw_ipfrag_list_t *raw_ipfrag = NULL, *p = NULL;;

	memcpy(buf, PCAP_FILE_HEAD, sizeof(PCAP_FILE_HEAD));
	used_len += sizeof(PCAP_FILE_HEAD);

	gettimeofday(&t, NULL);
	ret = get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_DATA, &p_eth_rawpkt);
	switch(ret)
	{
		case 0:
			get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_TOT_LEN, &eth_rawpkt_len);
			
			pcap_hdr.tv_sec = t.tv_sec;
			pcap_hdr.tv_usec = t.tv_usec;
			pcap_hdr.caplen = eth_rawpkt_len;
			pcap_hdr.len = pcap_hdr.caplen;
			
			memcpy(buf+used_len, &pcap_hdr, sizeof(pcap_hdr));
			used_len += sizeof(pcap_hdr);

			if(eth_rawpkt_len <= 0 || p_eth_rawpkt == NULL)
			{
				return used_len;
			}

			min_len = MIN(eth_rawpkt_len, buflen-used_len);

			memcpy(buf+used_len, p_eth_rawpkt, min_len);
			used_len += min_len;
			break;
		case 1:
			raw_ipfrag = (raw_ipfrag_list_t *)p_eth_rawpkt;
			p = raw_ipfrag;
			while(p)
			{
				if(buflen < used_len+p->pkt_len+(int)sizeof(pcap_hdr))
				{
					assert(0);
					break;
				}

				pcap_hdr.tv_sec = t.tv_sec;
				pcap_hdr.tv_usec = t.tv_usec;
				pcap_hdr.caplen = eth_rawpkt_len;
				pcap_hdr.len = pcap_hdr.caplen;
				
				memcpy(buf+used_len, &pcap_hdr, sizeof(pcap_hdr));
				used_len += sizeof(pcap_hdr);
				
				memcpy(buf+used_len, p->frag_packet, p->pkt_len);
				used_len += p->pkt_len;
			}
			break;
		default:
			return 0;
			break;
	}
	
	return used_len;
}


int dns_save_error_pkt(const struct streaminfo * a_stream, int error_type)
{
	char buf[8*1024];
	char filename[128];
	int buflen = 8*1024;
	int used_len = 0;
	FILE *fp = NULL;

	switch(error_type)
	{
		case DNS_ERROR_QUESTION:
			return 0;
			break;
		case DNS_ERROR_UNKNOWN:
			return 0;
			break;
		case DNS_ERROR_CLASS_UNKNOWN:
			return 0;
			break;
		case DNS_ERROR_PAYLOAD_SHORT:
			return 0;
			break;
		case DNS_ERROR_RR:
			return 0;
			break;
		case DNS_ERROR_ALL:
			break;
		default:
			return 0;
			break;
	}
	used_len = dns_save_raw_pkt(buf, buflen, a_stream);
	snprintf(filename, sizeof(filename), "./log/dns/%s_%ld.pcap", printaddr(&a_stream->addr, a_stream->threadnum), random());
	snprintf(filename, sizeof(filename), "/dev/shm/pkt_dump/111_%d_%d.pcap", a_stream->threadnum, pcap_index);

	fp = fopen(filename, "w+");
	if(fp != NULL)
	{
		fwrite(buf, used_len, 1, fp);
		fclose(fp);
		fp = NULL;
	}
	
	return 0;	
}

int dns_compress_rr_str(unsigned char *domain, int domain_len, u_char *result)
{
	int section_len = 0;
	int result_pos = 1;
	int domain_pos = 0;

    if(domain_len < 0 || domain_len > DNS_MAX_NAME+1 ||
                '.' == domain[0] || '.' == domain[domain_len - 1])
    {
        return -1;
    }

	while((domain[domain_pos] != '\n')||(domain[domain_pos] != '\0'))
	{
		section_len = 0;
		while((domain[domain_pos] != '.') &&(domain[domain_pos] != '\n')&&(domain[domain_pos] != '\0'))
		{
			result[result_pos] = domain[domain_pos];
			result_pos++;
			domain_pos++;
			section_len++;
		}
		result[result_pos - section_len -1] = section_len;

		if((domain[domain_pos] == '\n')||(domain[domain_pos] == '\0'))
			break;
		result_pos++;
		domain_pos++;
	}

	result[result_pos]= '\0';

	if(result_pos >= domain_len)
	{
    	return result_pos+1;
	}
	else
	{
		return  result_pos;
	}

	return 0;
}


int set_cheat_pkt_question(unsigned char *payload, int payload_len, dns_query_question_t *query, int query_num)
{
	unsigned short tqtype = 0;
	unsigned short tqclass = 0;
	int compress_len = 0, used_len = 0;
	u_char compress_name[DNS_MAX_NAME+1];

	/* 只处理一个请求 */
	
	memset(compress_name, 0, sizeof(compress_name));
	compress_len = dns_compress_rr_str(query->qname,strlen((char *)(query->qname)), compress_name);
	memcpy(payload, compress_name, compress_len);
	
	used_len += compress_len ;

	tqtype = ntohs(query->qtype);
	memcpy(payload+used_len, &(tqtype), sizeof(query->qtype));
	used_len += sizeof(query->qtype);

	tqclass = ntohs(query->qclass);
	memcpy(payload+used_len, &(tqclass), sizeof(query->qclass));
	used_len += sizeof(query->qclass);

	return used_len;
}


int set_cheat_pkt_rr_pdata_type_str(unsigned char *payload, int payload_len, cheat_pkt_opt_t *cheat_opt)
{
	int used_len = 0;
	unsigned int seg_32 = 0;
	unsigned short seg_16 = 0;
	unsigned short q_class = 1;
	unsigned short compress_len = 0;
	u_char compress_name[DNS_MAX_NAME+1];
	
	seg_16 = htons(0xc00c);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/* type: 2byte */
	seg_16 = htons(cheat_opt->res_type);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/*class: 2byte */
	seg_16 = htons(q_class);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/*TTL: 2byte */
	seg_32 = htonl(cheat_opt->ttl);
	memcpy(payload + used_len, &seg_32, sizeof(seg_32));
	used_len += sizeof(seg_32);

	memset(compress_name, 0, sizeof(compress_name));
	compress_len = dns_compress_rr_str(cheat_opt->res_info, cheat_opt->res_len, compress_name);
	
	/*RR data length*/
	seg_16 = htons(compress_len);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	memcpy(payload + used_len, compress_name, compress_len);
	used_len += compress_len;
   
	return used_len;
}

int set_cheat_pkt_rr_pdata_type_ip(unsigned char *payload, int payload_len, cheat_pkt_opt_t *cheat_opt)
{
	int used_len = 0;
	unsigned int seg_32 = 0;
	unsigned short seg_16 = 0;
	unsigned short q_class = 1;

	seg_16 = htons(0xc00c);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/* type: 2byte */
	seg_16 = htons(cheat_opt->res_type);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/*class: 2byte */
	seg_16 = htons(q_class);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);

	/*TTL: 2byte */
	seg_32 = htonl(cheat_opt->ttl);
	memcpy(payload + used_len, &seg_32, sizeof(seg_32));
	used_len += sizeof(seg_32);
	
	/*RR data length*/
	seg_16 = htons(cheat_opt->res_len);
	memcpy(payload + used_len, &seg_16, sizeof(seg_16));
	used_len += sizeof(seg_16);
	
	memcpy(payload + used_len, (char *)cheat_opt->res_info, cheat_opt->res_len);
	used_len += cheat_opt->res_len;

   return used_len;
}


int set_cheat_pkt_header(dns_hdr_t *dns_hdr)
{
	dns_hdr->qr = 1;        // 1bit: Response
	dns_hdr->opcode = 0;    // 4bits: Query
	dns_hdr->aa = 0;        // 1bit: authoritative answer
	dns_hdr->tc = 0;        // 1bit: Not truncated
	dns_hdr->rd = 1;        // 1bit: Recursion Desired
	dns_hdr->ra = 1;        // 1bit: Recursion Available
	dns_hdr->z = 0;         // 3bits: Reserved for future use: Must be zero in all queries and responses
	dns_hdr->rcode = 0;     // 4bits: 0: No error condition

	dns_hdr->id = htons(dns_hdr->id);
	dns_hdr->qdcount = htons(dns_hdr->qdcount);  // 16bits: QDCOUNT: number of questions
	dns_hdr->ancount = htons(dns_hdr->ancount);  // 16bits: ANCOUNT: number of answer resource records
	dns_hdr->aucount = htons(dns_hdr->aucount);  // 16bits: NSCOUNT: number of authority resource records
	dns_hdr->adcount = htons(dns_hdr->adcount);  // 16bits: ARCOUNT: number of additional resource records

	return 0;
}

int build_cheat_pkt(unsigned char *payload, int payload_len, dns_query_question_t *query_question, cheat_pkt_opt_t *cheat_opt, int cheat_opt_num)
{
	int i = 0, rr_count = 0;
	dns_hdr_t *dns_hdr = NULL;
	int used_len = 0;

	dns_hdr = (dns_hdr_t *)payload;
	
	used_len += sizeof(dns_hdr_t);
	used_len += set_cheat_pkt_question(payload+used_len, payload_len-used_len, query_question, dns_hdr->qdcount);

	rr_count = dns_hdr->adcount + dns_hdr->ancount + dns_hdr->aucount;

	for(i = 0; i < rr_count; i++)
	{
		switch(cheat_opt[i].res_type)
		{
			case DNS_TYPE_A:
			case DNS_TYPE_AAAA:
				used_len += set_cheat_pkt_rr_pdata_type_ip(payload+used_len, payload_len, &cheat_opt[i]);
				break;
			case DNS_TYPE_CNAME:
			case DNS_TYPE_NS:
				used_len += set_cheat_pkt_rr_pdata_type_str(payload+used_len, payload_len, &cheat_opt[i]);
				break;
		}

		if(used_len > payload_len)
		{
			return -1;
		}
	}

	set_cheat_pkt_header(dns_hdr);

	return used_len;
}


int check_port(struct layer_addr addr, unsigned short port)
{
	struct stream_tuple4_v4 *tpl4 = NULL;
	struct stream_tuple4_v6 *tpl6 = NULL;

	switch(addr.addrtype)
	{
		case ADDR_TYPE_IPV4:
			tpl4=addr.tuple4_v4;
			if((ntohs(tpl4->source) != port) && (ntohs(tpl4->dest) != port))
			{
				return 0;
			}
			break;
		case ADDR_TYPE_IPV6:
			tpl6=addr.tuple4_v6;
			if((ntohs(tpl6->source) != port) && (ntohs(tpl6->dest) != port))
			{
				return 0;
			}
			break;
		default:
			break;
	}

	return 1;	
}

void free_dns_info(dns_info_t *dns_info)
{
	int i = 0;
	
	if(dns_info->query_question != NULL)
	{
		free(dns_info->query_question);
		dns_info->query_question = NULL;
	}

	if(dns_info->rr != NULL && dns_info->rr_count > 0)
	{
		for(i = 0; i < dns_info->rr_count; i++)
		{
			switch(dns_info->rr[i].type)
			{
				case DNS_TYPE_NSEC3:
					if(dns_info->rr[i].rdata.cname != NULL)
					{
						if(dns_info->rr[i].rdata.nsec3->salt_value != NULL)
						{
							free(dns_info->rr[i].rdata.nsec3->salt_value);
							dns_info->rr[i].rdata.nsec3->salt_value = NULL;
						}

						if(dns_info->rr[i].rdata.nsec3->next_hash_owner != NULL)
						{
							free(dns_info->rr[i].rdata.nsec3->next_hash_owner);
							dns_info->rr[i].rdata.nsec3->next_hash_owner = NULL;
						}
							
						free(dns_info->rr[i].rdata.cname);
						dns_info->rr[i].rdata.cname = NULL;
					}
					break;
				default:
					if(dns_info->rr[i].rdata.cname != NULL)
					{
						free(dns_info->rr[i].rdata.cname);
						dns_info->rr[i].rdata.cname = NULL;
					}
					break;
			}
		}

		free(dns_info->rr);
		dns_info->rr = NULL;
	}
}
int get_dns_hdr_info(dns_hdr_t *dns_hdr, char *payload)
{
	dns_hdr_t *tmp = ((dns_hdr_t *)payload);
	memset(dns_hdr, 0, sizeof(dns_hdr_t));
/*
	dns_hdr->qr = ntohs(tmp->qr);
	dns_hdr->opcode= ntohs(tmp->opcode);
	dns_hdr->aa = ntohs(tmp->aa);
	dns_hdr->tc = ntohs(tmp->tc);
	dns_hdr->rd = ntohs(tmp->rd);
	dns_hdr->ra = ntohs(tmp->ra);
	dns_hdr->z = ntohs(tmp->z);
	dns_hdr->rcode = ntohs(tmp->rcode);
*/
	dns_hdr->qr = tmp->qr;
	dns_hdr->opcode= tmp->opcode;
	dns_hdr->aa = tmp->aa;
	dns_hdr->tc = tmp->tc;
	dns_hdr->rd = tmp->rd;
	dns_hdr->ra = tmp->ra;
	dns_hdr->z = tmp->z;
	dns_hdr->rcode = tmp->rcode;

	dns_hdr->id = ntohs(tmp->id);
	dns_hdr->qdcount = ntohs(tmp->qdcount);
	dns_hdr->ancount = ntohs(tmp->ancount);
	dns_hdr->aucount = ntohs(tmp->aucount);
	dns_hdr->adcount = ntohs(tmp->adcount);
	
	return 0;
}
int get_rr_type_nsec3(char **ptr, nsec3_t *nsec3, char *end)
{
	nsec3->hash_algo = *(unsigned char *)*ptr;
	*ptr += 1;
	nsec3->flags= *(unsigned char *)*ptr;
	*ptr += 1;			
	NS_GET16(nsec3->iteration, *ptr);
	nsec3->salt_len = *(unsigned char *)*ptr;
	*ptr += 1;
	nsec3->salt_value = (unsigned char *)calloc(1, nsec3->salt_len+1);	/* jump nsec3_t */
	memcpy(nsec3->salt_value, *ptr, nsec3->salt_len);
	*ptr += nsec3->salt_len;	/* jump salt_value */
	
	nsec3->hash_len = *(unsigned char *)*ptr;
	*ptr += 1;
	nsec3->next_hash_owner = (unsigned char *)calloc(1, nsec3->hash_len+1);	
	memcpy(nsec3->next_hash_owner, *ptr, nsec3->hash_len);
	*ptr += nsec3->hash_len;/* jump next_hash_owner */
		
	return 0;
}

int get_rr_signer(unsigned char ** ptr, unsigned char *buf, int buflen, char* end)
{
	unsigned char *p = NULL;
	int len = 0, i = 0;

	p = *ptr;
	if(0 == p[0])
	{
		len = strlen("Root");
		memcpy(buf, "Root", len);
		buf[len] = '\0';
		*ptr += 1;
		return 1;
	}

	p = *ptr;
	*ptr = NULL;
	len = 0;
	
	while(1) 
	{
		len++;
		if(0x03 == p[0])
		{
			p += 1;
			continue;
		}
		
		buf[i++] = p[0];
		p += 1;
		
		if(0 == p[0])
		{
			len++;
			p += 1;
			break;
		}
	}

	*ptr = p;
	buf[i] = '\0';
		
	return len;
}
int get_rr_type_rrsig(char **ptr, rrsig_t *rrsig, char *end)
{
	NS_GET16(rrsig->type_covered, *ptr);
	rrsig->algo = *(unsigned char *)ptr;
	*ptr += 1;
	rrsig->labels = *(unsigned char *)ptr;
	*ptr += 1;
	NS_GET32(rrsig->original_ttl, *ptr);
	NS_GET32(rrsig->sig_expiration, *ptr);
	NS_GET32(rrsig->sig_inception, *ptr);
	NS_GET16(rrsig->key_tag, *ptr);

	return 0;
}

int get_rr_type_wks(char **ptr, wks_t *wks, char *end)
{
	if(* ptr + 4 > end) return -1;
	NS_GET32(wks->addr, * ptr);
	if(* ptr + 1 > end) return -1;
	wks->protocol = *(unsigned char *)ptr;
	*ptr += 1;
	wks->bitmap = *(u_char**)ptr;

	return 0;
}

int get_rr_type_soa(char *msg, char **ptr, soa_t *soa, char *end)
{
	if(0 >= get_rr_domain(msg, (unsigned char**)ptr, soa->mname, sizeof(soa->mname), end))
		return -1;
	if(0 >= get_rr_domain(msg, (unsigned char**)ptr, soa->rname, sizeof(soa->rname), end))
		return -1;
	
	if(* ptr + 4 > end) return -1;
	NS_GET32(soa->serial, *ptr);
	if(* ptr + 4 > end) return -1;
	NS_GET32(soa->refresh, *ptr);
	if(* ptr + 4 > end) return -1;
	NS_GET32(soa->retry, *ptr);
	if(* ptr + 4 > end) return -1;
	NS_GET32(soa->expire, *ptr);
	if(* ptr + 4 > end) return -1;
	NS_GET32(soa->minimum, *ptr);

	return 0;
}

int get_rr_type_info(char **ptr, hinfo_t *hinfo, char *end)
{
	int len = 0;
	hinfo->cpu_len = ((unsigned char *)ptr)[0];
	*ptr += 1;
	len = MIN(hinfo->cpu_len, sizeof(DNS_HINFO_MAX_CPU-1));
	memcpy((char *)hinfo->cpu, *ptr, len);
	*ptr += hinfo->cpu_len;
	hinfo->cpu_len = len;
	
	hinfo->os_len = ((unsigned char *)ptr)[0];
	*ptr += 1;
	len = MIN(hinfo->os_len, sizeof(DNS_HINFO_MAX_OS-1));
	memcpy((char *)hinfo->os, *ptr, len);
	*ptr += hinfo->os_len;
	hinfo->os_len = len;
	
	return 0;
}

int get_decompressed_name(char * msg, unsigned char**ptr, unsigned char *buf, int buflen, char *end)
{
	unsigned char *p = NULL;
	int index = 0, len = 0;
	int np = 0, tot_len = 0;

	p = *ptr;
	*ptr = NULL;
	index = 0;
	np = 0;
	while(1) 
	{
		if(0 == p[0])
		{
			break;
		}

		if(0x0c0 == (p[0] & 0x0c0))
		{
			if(p + 2 > (unsigned char *)end)
				return -1;
			
			len = ((p[0] & 0x03f) << 8) + p[1];

			if(NULL == * ptr)
			{
				tot_len += 2;
				*ptr = p + 2;
			}

			p =(unsigned char*) msg + len;
			if(p > (unsigned char *)end)
				return -1;

			/* too many pointers. */
			if(np ++ > 16) 
				return -1;
			
			continue;
		}

		
		len = p[0];
		p ++;
		tot_len++;

		if(p + len > (unsigned char *)end)
			return -1;
		
		if(index + len >= buflen - 1)
			return -1;
		
		memcpy(buf + index, p, len);
		index += len;
		buf[index ++] = '.';
		p += len;
		tot_len +=len;
	}
	
	if(NULL == *ptr)
	{
		*ptr = p + 1;
		tot_len++;
	}
	/*
	 * omit last '.'
	 */
	if(index>0)
	{
		buf[index-1]='\0';
	}
	else
	{
		buf[0]='\0';
	}
	
	return tot_len;
}


int get_rr_domain( char * msg,unsigned char ** ptr, unsigned char * buf, int buflen, char * end)
{
	return get_decompressed_name(msg, ptr, buf, buflen, end);
}

int get_rr_common_field(char *msg, char **ptr, dns_rr_t *rr,  char *end)
{
	char * p = NULL;
	if(*ptr==NULL) 
	{
		return -1;
	}
	
	get_rr_domain(msg, (unsigned char**)ptr, rr->name, DNS_MAX_NAME+1, end);
#if 0
	if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->name, DNS_MAX_NAME+1, end))
	{
		return -1;
	}
#endif
	if(*ptr==NULL || *ptr+2>end) 
	{
		return -1;
	}
	NS_GET16(rr->type, *ptr);
	
	if(*ptr==NULL || *ptr+2>end)
	{
		return -1;
	}

	NS_GET16(rr->rr_class, *ptr);

	if(DNS_CLASS_UNKNOWN == rr->rr_class) 
	{
		return -1;
	}

	if(*ptr==NULL || *ptr+4>end) 
	{
		return -1;
	}
	NS_GET32(rr->ttl, * ptr);
	if(*ptr==NULL || *ptr+2>end) 
	{
		return -1;
	}
	NS_GET16(rr->rdlength, * ptr);
	p = *ptr + rr->rdlength;
	if(*ptr==NULL || p>end) 
	{
		return -1;
	}

	return 0;
}

int callback_dns_business_plug(struct streaminfo *a_stream, void **pme, void *info, int prot_flag, int session_state, int thread_seq, void *a_packet)
{
	stSessionInfo sessionInfo;	
	save_dns_business_info_t *apme = (save_dns_business_info_t *)*pme;

	memset(&sessionInfo, 0, sizeof(stSessionInfo));
	
	sessionInfo.plugid = dns_plugid;
	sessionInfo.session_state = session_state;
	sessionInfo.prot_flag = prot_flag;
	sessionInfo.app_info = (void *)info;
	PROT_PROCESS(&sessionInfo, &apme->business_pme, thread_seq, a_stream, a_packet);

	return 0;
}

int get_dns_query_question(char *msg, char **ptr, dns_query_question_t *q, char *end)
{
	int used_len = 0;
	if(0 >= get_rr_domain(msg, (unsigned char**)ptr, q->qname, DNS_MAX_NAME+1, end))
	{
		return -1;
	}

	used_len = strlen((char *)q->qname);
	if(q->qname[used_len-1]=='.')
		return -2;
	
	if(* ptr + 2 > end)
	{
		return -1;
	}
	
	NS_GET16(q->qtype, *ptr);

	if(* ptr + 2 > end) 
	{
		return -1;
	}
	
	NS_GET16(q->qclass, *ptr);
	
	return 0;
}

int get_one_resource_record(char * msg, char ** ptr, dns_rr_t * rr,  char * end)
{	
	//int salt_len = 0, hash_len = 0;
	unsigned int len = 0, byte = 0;
	unsigned char *original_ptr = NULL;
	
	switch(rr->type) 
	{
		case DNS_TYPE_CNAME:
			original_ptr = (unsigned char*)*ptr;
			rr->rdata.cname = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.cname, DNS_MAX_NAME+1, end))
			{
				return 0;
			}
			
			break;
		case DNS_TYPE_HINFO:
			rr->rdata.hinfo = (hinfo_t *)calloc(1, sizeof(hinfo_t));
			if(0 != get_rr_type_info(ptr, rr->rdata.hinfo, end))
			{
				return 0;
			}
			break;
		case DNS_TYPE_MB:
			rr->rdata.mb = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.mb, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MD:
			rr->rdata.md = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**) ptr, rr->rdata.md, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MF:
			rr->rdata.mf = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.mf, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MG:
			rr->rdata.mg = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.mg, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MINFO:
			rr->rdata.minfo = (minfo_t *)calloc(1, sizeof(minfo_t));
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.minfo->rmailbx, DNS_MAX_NAME+1, end))
				return 0;
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.minfo->emailbx, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MR:
			rr->rdata.mr = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg,(unsigned char**) ptr, rr->rdata.mr, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_MX:
			if(*ptr + 2 > end) return 0;
			rr->rdata.mx = (mx_t *)calloc(1, sizeof(mx_t));
			NS_GET16(rr->rdata.mx->preference, *ptr);
			if(rr->rdlength - 2 < ((unsigned char *)*ptr)[0])
			{
				if(rr->rdlength < 2)
				{
					*ptr += rr->rdlength;
					break;
				}
				len = MIN(DNS_MAX_NAME-1, rr->rdlength-2);/*size=1byte*/
				memcpy(rr->rdata.mx->exchange, *ptr, len);	/* error labels */
				*ptr += rr->rdlength-2;
			}
			else
			{
				if(0 >= get_rr_domain(msg,(unsigned char**) ptr, rr->rdata.mx->exchange, DNS_MAX_NAME+1, end))
					return 0;
			}
			break;
		case DNS_TYPE_NS:
			rr->rdata.ns = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg,(unsigned char**) ptr, rr->rdata.ns, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_PTR:
			rr->rdata.ptr = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.ptr, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_SOA:
			original_ptr = (unsigned char*)*ptr;
			rr->rdata.soa = (soa_t *)calloc(1, sizeof(soa_t));
			if(0 != get_rr_type_soa(msg, ptr, rr->rdata.soa, end))
				return 0;
			if((char *)original_ptr+rr->rdlength!=*ptr)
			{
				*ptr=(char *)original_ptr+rr->rdlength;
			}
			break;
		case DNS_TYPE_A:
			if(* ptr + 4 > end) return 0;
			rr->rdata.a = (u_char *)calloc(1, NS_INT32SZ+1);
			memcpy(rr->rdata.a, *ptr, NS_INT32SZ);
			(*ptr) += NS_INT32SZ;
			break;
		case DNS_TYPE_AAAA:
			if(* ptr + 16 > end) return -1;
			rr->rdata.aaaa = (u_char *)calloc(1, 17);
			memcpy(rr->rdata.aaaa, *ptr, 16);
			(*ptr)+=16;
			break;
		case DNS_TYPE_DNAME:
			rr->rdata.dname = (u_char *)calloc(1, DNS_MAX_NAME+1);
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.dname, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_ISDN:
			rr->rdata.isdn = (u_char *)calloc(1, 1);
			memcpy(rr->rdata.isdn, *ptr, sizeof(u_char));
			(*ptr)+=1;
			break;
		case DNS_TYPE_TXT:
			rr->rdata.txt = (txt_t *)calloc(1, sizeof(txt_t));
			len = MIN(DNS_MAX_NAME-1, rr->rdlength-1);/*size=1byte*/
			memcpy(rr->rdata.txt->txt, *ptr+1, len);
			rr->rdata.txt->size = len;	
			*ptr += rr->rdlength;
			break;
		case DNS_TYPE_RP:
			rr->rdata.rp = (rp_t *)calloc(1, sizeof(rp_t));
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.rp->mailbox, DNS_MAX_NAME+1, end))
				return 0;
			if(0 >= get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.rp->txt_rr, DNS_MAX_NAME+1, end))
				return 0;
			break;
		case DNS_TYPE_NULL:
			rr->rdata.null = (null_t *)calloc(1, sizeof(null_t));
			len = MIN(DNS_MAX_NAME-1, rr->rdlength-1);	/*size=1byte*/
			memcpy(rr->rdata.null->null, *ptr+1, len);
			rr->rdata.null->size = len;
			*ptr += rr->rdlength;
			break;
		case DNS_TYPE_WKS:
			rr->rdata.wks = (wks_t *)calloc(1, sizeof(wks_t));
			if(0 != get_rr_type_wks(ptr, rr->rdata.wks, end))
				return 0;
			rr->rdata.wks->size = rr->rdlength - 5;
			*ptr += rr->rdlength - 5;
		case DNS_TYPE_SRV:
			rr->rdata.srv = (srv_t *)calloc(1, sizeof(srv_t));
			NS_GET16(rr->rdata.srv->priority, *ptr);
			NS_GET16(rr->rdata.srv->weight, *ptr);
			NS_GET16(rr->rdata.srv->port, *ptr);
			if(0 >= get_rr_domain(msg,(unsigned char**) ptr, rr->rdata.srv->target, DNS_MAX_TARGET, end))
				return 0;
			break;
		case DNS_TYPE_OPT:
			break;
		case DNS_TYPE_DS:
		case DNS_TYPE_DLV:
			if(* ptr + 4 > end) return 0;
			rr->rdata.ds = (ds_t *)calloc(1, sizeof(ds_t));
			NS_GET16(rr->rdata.ds->key_tag, *ptr);
			rr->rdata.ds->algo = *(unsigned char *)ptr;
			*ptr += 1;
			rr->rdata.ds->digest_type = *(unsigned char *)ptr;
			*ptr += 1;
			rr->rdata.ds->digest = *(u_char**)ptr;
			rr->rdata.ds->digest_len = rr->rdlength - 4;
			*ptr += rr->rdlength - 4;
			break;
		case DNS_TYPE_RRSIG:
			if(* ptr + 18 > end) return 0;
			rr->rdata.rrsig = (rrsig_t *)calloc(1, sizeof(rrsig_t));
			get_rr_type_rrsig(ptr, rr->rdata.rrsig, end);
			len = get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.rrsig->signer_name, DNS_MAX_SIGNER_NAME, end);
			if(len <= 0)
			{
				return -1;
			}
			rr->rdata.rrsig->signature = *(u_char**)ptr;
			rr->rdata.rrsig->signature_len = rr->rdlength - 18 - len;
			*ptr += rr->rdlength - 18 - len;
			break;
		case DNS_TYPE_NSEC:
			original_ptr = (unsigned char*)*ptr;
			rr->rdata.nsec = (nsec_t *)calloc(1, sizeof(nsec_t));
			len = get_rr_domain(msg, (unsigned char**)ptr, rr->rdata.nsec->next_domain, DNS_MAX_OWNER, end);
			if(len <= 0)
			{
				return -1;
			}
			
			if((original_ptr+rr->rdlength != (unsigned char*)*ptr) && (*ptr != NULL))
			{
				NS_GET16(len, *ptr);
				byte = MIN(DNS_MAX_MAPS-1, len);
				memcpy(rr->rdata.nsec->type_bit_maps, *ptr, byte);
				*ptr += len;
				rr->rdata.nsec->maps_len = len;
				len = byte;

				byte = ((unsigned char *)ptr)[0];
				if((byte&0xFF) == 0xFF || byte == 128)
				{
					*ptr += 1;	/* jump 0xFF */
					byte = ((unsigned char *)ptr)[0];
					*ptr += 1;	/* jump 1 byte of len */
					len = MIN(DNS_MAX_MAPS-1-len, byte);
					memcpy(rr->rdata.nsec->type_bit_maps+rr->rdata.nsec->maps_len, *ptr, len);
					*ptr += byte;	/* jump  byte */
					rr->rdata.nsec->maps_len += len;
				}
			}
			break;
		case DNS_TYPE_DNSKEY:
			if(* ptr + 4 > end) return 0;			
			rr->rdata.dnskey = (dnskey_t *)calloc(1, sizeof(dnskey_t));			
			NS_GET16(rr->rdata.dnskey->flags, *ptr);
			rr->rdata.dnskey->protocol = *(unsigned char *)ptr;
			*ptr += 1;
			rr->rdata.dnskey->algo = *(unsigned char *)ptr;
			*ptr += 1;
			rr->rdata.dnskey->public_key = *(u_char**)ptr;
			rr->rdata.dnskey->public_key_len = rr->rdlength - 4;/* sizeof(flags)+sizeof(protocol)+sizeof(algo) */
			*ptr +=  rr->rdlength - 4; /* todo add log */
			break;
		case DNS_TYPE_NSEC3:
			if(* ptr + 5 > end) return 0;
			original_ptr = (unsigned char*)*ptr;
			//salt_len = *(unsigned char *)(*ptr+4);	/* salt length */
			//hash_len = *(salt_len + (unsigned char *)(*ptr+5));	/* hash length */
			rr->rdata.nsec3 = (nsec3_t *)calloc(1, sizeof(nsec3_t));
			get_rr_type_nsec3(ptr, rr->rdata.nsec3, end);

			if((original_ptr+rr->rdlength != (unsigned char*)*ptr) && (*ptr != NULL))
			{
				NS_GET16(len, *ptr);
				byte = MIN(DNS_MAX_MAPS-1, len);
				memcpy( rr->rdata.nsec3->type_bit_maps, *ptr, byte);
				*ptr += len;
				rr->rdata.nsec3->maps_len = byte;
				len = byte;

				byte = ((unsigned char *)*ptr)[0];
				if((byte&0xFF) == 0xFF || byte == 128)
				{
					*ptr += 1;	/* jump 0xFF */
					byte = ((unsigned char *)*ptr)[0];
					*ptr += 1;	/* jump 1 byte of len */
					len = MIN(DNS_MAX_MAPS-1-len, byte);
					memcpy(rr->rdata.nsec3->type_bit_maps+rr->rdata.nsec3->maps_len, *ptr, len);
					*ptr += byte;	/* jump  byte */
					rr->rdata.nsec3->maps_len += len;
				}
			}
			break;
		case DNS_TYPE_NSEC3PARAM:
			rr->rdata.nsec3param = (nsec3param_t *)calloc(1, sizeof(nsec3param_t));	
			rr->rdata.nsec3param->hash_algo = *(unsigned char *)ptr;
			*ptr += 1;
			rr->rdata.nsec3param->flags = *(unsigned char *)ptr;
			*ptr += 1;
			NS_GET16(rr->rdata.nsec3param->iteration, *ptr);
			rr->rdata.nsec3param->salt_len = rr->rdlength -4-1;
			*ptr += 1;
			rr->rdata.nsec3param->salt_value = *(u_char**)ptr;
			*ptr +=  rr->rdlength-5;
			break;
		case DNS_TYPE_UNKNOWN:
			rr->rdata.unknown_data = (u_char *)calloc(1, rr->rdlength+1);
			memcpy(rr->rdata.unknown_data, *ptr, rr->rdlength);
			(*ptr)+=rr->rdlength;
			break;
		default:
			*ptr +=  rr->rdlength;
			MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_INFO, "get_one_rr", "No support respone type, type: %d", rr->type);
			break;
	}
	
	return 1;
}

int parse_query_question(struct streaminfo *a_stream, dns_info_t *dns_info, char *payload, int payload_len, char **cur_pos)
{
	int ret = 0;

	if(0 == dns_info->hdr_info.qdcount || dns_info->hdr_info.qdcount > 1)
	{
		return APP_STATE_GIVEME;
	}
	
	dns_info->query_question = (dns_query_question_t *)calloc(dns_info->hdr_info.qdcount, sizeof(dns_query_question_t));

	if(0 != (ret = get_dns_query_question(payload, cur_pos, dns_info->query_question, payload+payload_len)))
	{
		if(ret == -2)
		{
			dns_save_error_pkt(a_stream, DNS_ERROR_QUESTION);
		}
		 return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}


int parse_resource_record(struct streaminfo *a_stream, dns_info_t *dns_info, char *payload, int payload_len,  char **cur_pos, int rr_type)
{
	int i = 0;
	
	switch(rr_type)
	{
		case DNS_RR_TYPE_ALL:
			dns_info->rr_count = dns_info->hdr_info.ancount + dns_info->hdr_info.adcount + dns_info->hdr_info.aucount;
			break;
		case DNS_RR_TYPE_ANS:
			dns_info->rr_count = dns_info->hdr_info.ancount;
			break;
		case DNS_RR_TYPE_AUTH:
			dns_info->rr_count = dns_info->hdr_info.ancount;
			/* todo */
			dns_info->rr_count = dns_info->hdr_info.aucount;
			break;
		case DNS_RR_TYPE_ADD:
			dns_info->rr_count = dns_info->hdr_info.ancount + dns_info->hdr_info.aucount;
			/* todo */
			dns_info->rr_count = dns_info->hdr_info.adcount;
			break;
		default:
			break;
	}

	if(dns_info->rr_count == 0)
	{
		return APP_STATE_GIVEME;
	}
	dns_info->rr = (dns_rr_t *)calloc(dns_info->rr_count, sizeof(dns_rr_t));

	for(i = 0; i < dns_info->rr_count; i++)
	{
		if((unsigned char *)*cur_pos >= (unsigned char *)payload+payload_len || (unsigned char *)*cur_pos < (unsigned char *)payload)
		{
			dns_save_error_pkt(a_stream, DNS_ERROR_PAYLOAD_SHORT);
			return APP_STATE_DROPME;
		}
		
		if(0 != get_rr_common_field(payload, cur_pos, &dns_info->rr[i], payload+payload_len))
		{
			if(dns_info->rr[i].rr_class == DNS_CLASS_UNKNOWN)
			{
				dns_save_error_pkt(a_stream, DNS_ERROR_CLASS_UNKNOWN);
				return APP_STATE_DROPME;	/* error packet */		
			}
			else
			{
				dns_save_error_pkt(a_stream, DNS_ERROR_UNKNOWN);
				dns_info->rr_count -= 1;
				i -= 1;
				continue;
			}
		}

		if(dns_info->rr[i].rdlength == 0)
		{
			continue;
		}
		
		if(!get_one_resource_record(payload, cur_pos, &dns_info->rr[i], payload+payload_len))
		{
			if(dns_info->rr[i].rdata.cname != NULL)
			{
				free(dns_info->rr[i].rdata.cname);
				dns_info->rr[i].rdata.cname = NULL;
			}
			dns_save_error_pkt(a_stream, DNS_ERROR_RR);
			dns_info->rr_count -= 1;
			i -= 1;
		}
	}

	assert(i==dns_info->rr_count);

	return APP_STATE_GIVEME;
}

int parse_dns_protocol(struct streaminfo *a_stream, unsigned char opstate, char *payload, int payload_len, void **pme, int thread_seq, void *a_packet)
{
	int i = 0;
	int session_state = SESSION_STATE_PENDING;
	int ret = APP_STATE_GIVEME;
	char *cur_pos = NULL;
	dns_info_t dns_info;
	unsigned long long register_flag = dns_register_flag;
	save_dns_business_info_t *context = (save_dns_business_info_t *)(*pme);

	if(payload_len < 12 )
	{
		FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[ERR_PKT], 0, FS_OP_ADD, 1);		
		MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_FATAL, "parse_dns_protocol", "tuple4: %s payload_len < 12", printaddr(&a_stream->addr, thread_seq));
		return APP_STATE_DROPME;
	}

	memset(&dns_info, 0, sizeof(dns_info_t));
	get_dns_hdr_info(&dns_info.hdr_info, payload);

	cur_pos = payload + sizeof(dns_hdr_t);

	for(i = 0; i < dns_register_flag_num; i++)
	{
		if(opstate != OP_STATE_CLOSE)
		{
			if(context->session_state&SESSION_STATE_PENDING)
			{
				session_state = SESSION_STATE_DATA;
			}
			else
			{
				session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA;
			}
			context->session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA;
		}
		else
		{
			if(context->session_state&SESSION_STATE_PENDING)
			{
				session_state = SESSION_STATE_CLOSE;
			}
			else
			{
				session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA|SESSION_STATE_CLOSE;
			}
		}

		if(register_flag&DNS_ALL)
		{
			register_flag = SET_BIT(register_flag, DNS_ALL);

			ret = parse_query_question(a_stream, &dns_info, payload, payload_len, &cur_pos);	
			if(ret == APP_STATE_DROPME)
			{				
				FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[ERR_PKT], 0, FS_OP_ADD, 1);				
				MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_DEBUG, "parse_dns_protocol", "parse_query_question return APP_STATE_DROPME, tuple4: %s, question_num: %d", printaddr(&a_stream->addr, thread_seq), dns_info.hdr_info.qdcount);
				free_dns_info(&dns_info);
				return APP_STATE_DROPME;
			}
			
			ret = parse_resource_record(a_stream, &dns_info, payload, payload_len, &cur_pos, DNS_RR_TYPE_ALL);	
			if(ret == APP_STATE_DROPME)
			{					
				FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[ERR_PKT], 0, FS_OP_ADD, 1);
				MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_DEBUG, "parse_dns_protocol", "parse_resource_record return APP_STATE_DROPME, tuple4: %s", printaddr(&a_stream->addr, thread_seq));
				free_dns_info(&dns_info);
				return APP_STATE_DROPME;
			}

			callback_dns_business_plug(a_stream, pme, (void *)&dns_info, DNS_ALL, session_state, thread_seq, a_packet);
		}
		else if((register_flag&DNS_REQ_ALL) && (0 == dns_info.hdr_info.qr))		/* process query packet */
		{
			register_flag = SET_BIT(register_flag, DNS_REQ_ALL);
			
			ret = parse_query_question(a_stream, &dns_info, payload, payload_len, &cur_pos);
		}
		else if((register_flag&DNS_REQ_HDR) && (0 == dns_info.hdr_info.qr))		/* process query packet */
		{
			register_flag = SET_BIT(register_flag, DNS_REQ_HDR);
		}
		else if((register_flag&DNS_RES_ALL) && (1 == dns_info.hdr_info.qr))		/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_ALL);
		}
		else if((register_flag&DNS_RES_HDR) && (1 == dns_info.hdr_info.qr))		/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_HDR);
		}
		else if((register_flag&DNS_RES_QUERY) && (1 == dns_info.hdr_info.qr))	/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_QUERY);
		}
		else if((register_flag&DNS_RES_RRS) && (1 == dns_info.hdr_info.qr))		/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_RRS);
		}
		else if((register_flag&DNS_RES_ANSWER) && (1 == dns_info.hdr_info.qr))	/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_ANSWER);
		}
		else if((register_flag&DNS_RES_AUTH) && (1 == dns_info.hdr_info.qr))	/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_AUTH);
		}
		else if((register_flag&DNS_RES_ADD) && (1 == dns_info.hdr_info.qr))		/* process response packet */
		{
			register_flag = SET_BIT(register_flag, DNS_RES_ADD);
		}
		else
		{
			
		}

		if(i != 0)
			continue;

		if(1 == dns_info.hdr_info.qr)	/* process response packet */
		{			
			FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[R_PKT], 0, FS_OP_ADD, 1); 	
		}
		else
		{
			if(dns_info.query_question==NULL)
			{
				FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_QUESTION], 0, FS_OP_ADD, 1); 
			}
			else
			{
				switch(dns_info.query_question->qtype)
				{
					case DNS_TYPE_A:
						FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_A], 0, FS_OP_ADD, 1);		
						break;
					case DNS_TYPE_AAAA:
						FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_AAAA], 0, FS_OP_ADD, 1);		
						break;
					case DNS_TYPE_CNAME:
						FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_CNAME], 0, FS_OP_ADD, 1);		
						break;
					default:
						FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_UNKNOWN], 0, FS_OP_ADD, 1); 	
						break;
				}
			}
			
			FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[Q_PKT], 0, FS_OP_ADD, 1); 	
		}
	}

	free_dns_info(&dns_info);

	return APP_STATE_GIVEME;
}

char DNS_UDP_ENTRY(struct streaminfo *a_udp, void **pme, int thread_seq, void *a_packet)
{
	int payload_len = 0;
	char *payload = NULL;
	struct udpdetail *udp_detail = NULL;
	 
	if(!check_port(a_udp->addr, DNS_PORT))
	{
		return APP_STATE_DROPME;
	}
	
	udp_detail =  (struct udpdetail *)a_udp->pudpdetail;
	payload_len = udp_detail->datalen;
	payload = (char *)udp_detail->pdata;

	switch(a_udp->opstate)
	{
		case OP_STATE_PENDING:
			if(*pme == NULL)
			{
				*pme = dictator_malloc(thread_seq, sizeof(save_dns_business_info_t));
				memset(*pme, 0, sizeof(save_dns_business_info_t));
			}
			/*   no break here!!!!  */
		case OP_STATE_DATA:
			switch(a_udp->addr.addrtype)
			{
				case ADDR_TYPE_IPV4:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V4_U_PPS], 0, FS_OP_ADD, 1);
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V4_U_BPS], 0, FS_OP_ADD, payload_len);
					break;
				case ADDR_TYPE_IPV6:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V6_U_PPS], 0, FS_OP_ADD, 1);
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V6_U_BPS], 0, FS_OP_ADD, payload_len);
					break;
				default:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[PKT_UNKNOWN], 0, FS_OP_ADD, 1);
					return APP_STATE_DROPME;
					break;
			}
			
			 parse_dns_protocol(a_udp, a_udp->opstate, payload, payload_len, pme, thread_seq, a_packet);
			break;
		case OP_STATE_CLOSE:
			callback_dns_business_plug(a_udp, pme, NULL, DNS_ALL, SESSION_STATE_CLOSE, thread_seq, a_packet);
			dictator_free(thread_seq, *pme);
			*pme = NULL;
			break;
	}

	return APP_STATE_GIVEME;
}


char DNS_TCP_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq, void *a_packet)
{
	int payload_len = 0;
	char *payload = NULL;
	struct tcpdetail* tcp_detail = (struct tcpdetail*)a_tcp->pdetail;

	if(!check_port(a_tcp->addr, DNS_PORT))
	{
		return APP_STATE_DROPME;
	}
	
	tcp_detail = (struct tcpdetail *)a_tcp->ptcpdetail;
	payload_len = tcp_detail->datalen;
	payload = (char *)tcp_detail->pdata;

	payload_len -= 2; 	/* 2015-09-29 lijia add, TCP协议头部前有2个字节长度信息 */
	payload += 2; 		/* 2015-09-29 lijia add, TCP协议头部前有2个字节长度信息 */

	switch(a_tcp->opstate)
	{
		case OP_STATE_PENDING: /* 暂未保存上下文信息 */
			if((NULL == tcp_detail->pdata) || (0 == tcp_detail->datalen))
			{
				return APP_STATE_GIVEME;
			}
			
			if(*pme == NULL)
			{
				*pme = dictator_malloc(thread_seq, sizeof(save_dns_business_info_t));
				memset(*pme, 0, sizeof(save_dns_business_info_t));
			}
		/*   no break here!!!!  */
		case OP_STATE_DATA:
			
			switch(a_tcp->addr.addrtype)
			{
				case ADDR_TYPE_IPV4:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V4_T_PPS], 0, FS_OP_ADD, 1);
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V4_T_BPS], 0, FS_OP_ADD, payload_len);
					break;
				case ADDR_TYPE_IPV6:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V6_T_PPS], 0, FS_OP_ADD, 1);
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[V6_T_BPS], 0, FS_OP_ADD, payload_len);
					break;
				default:
					FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[PKT_UNKNOWN], 0, FS_OP_ADD, 1);
					return APP_STATE_DROPME;
					break;
			}
#if 0			
            if((tcp_detail->serverbytes < 2) ||(tcp_detail->clientbytes >= 1500))
			{
				FS_operate(g_dns_proto_info.stat_handle, g_dns_proto_info.fild_id[ERR_PKT], 0, FS_OP_ADD, 1);
				MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_DEBUG, "TCP_ENTRY",
									"tuple4: %s PKT size(S: %d/C: %d) is too litter or bigger", printaddr(&a_tcp->addr, thread_seq), tcp_detail->serverbytes, tcp_detail->clientbytes);
            	return APP_STATE_GIVEME;
			}
#endif		
			parse_dns_protocol(a_tcp, a_tcp->opstate, payload, payload_len, pme, thread_seq, a_packet);
			break;
		case OP_STATE_CLOSE:
			callback_dns_business_plug(a_tcp, pme, NULL, DNS_UNKOWN, SESSION_STATE_CLOSE, thread_seq, a_packet);			
			dictator_free(thread_seq, *pme);
			*pme = NULL;
			break;
	}

	return APP_STATE_GIVEME;
}


/****************************************************************************
??????:DNS_INIT()
?????DNS??????????????????
??????
????????:plugid
		  ???:<0?????????
*****************************************************************************/
int DNS_INIT()
{
	pcap_index = random();
	int i = 0, value = 1;
	const char* fs_output_path="./dns_stat.log";
	memset(&g_dns_proto_info, 0, sizeof(g_dns_proto_info_t));
	
	MESA_load_profile_int_def(dns_conf_file, "DNS", "STAT_CYCLE", &g_dns_proto_info.cycle_time, 2);
	MESA_load_profile_int_def(dns_conf_file, "DNS", "LOG_LEVEL", &g_dns_proto_info.log_level, 30);
	MESA_load_profile_string_def(dns_conf_file, "DNS", "LOG_PATH", g_dns_proto_info.log_path, MAX_LOG_PATH_LEN, NULL);
	
	g_dns_proto_info.logger = MESA_create_runtime_log_handle(g_dns_proto_info.log_path, g_dns_proto_info.log_level);
	if(g_dns_proto_info.logger == NULL)
	{
		printf("********************* DNS_INIT error ***************************\n");
		return -1;
	}

	g_dns_proto_info.stat_handle = FS_create_handle();

	FS_set_para(g_dns_proto_info.stat_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);
	value=1;//Rewrite
	FS_set_para(g_dns_proto_info.stat_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(g_dns_proto_info.stat_handle, CREATE_THREAD, &value, sizeof(value));
	
	FS_set_para(g_dns_proto_info.stat_handle, STAT_CYCLE, &g_dns_proto_info.cycle_time, sizeof(g_dns_proto_info.cycle_time));
	
	for(i = 0; DNS_STATIS_INFO[i].str != NULL && i == (int)DNS_STATIS_INFO[i].id && i < DNS_MAX_FIELD_ID_NUM; i++)
	{
		g_dns_proto_info.fild_id[DNS_STATIS_INFO[i].id] = FS_register(g_dns_proto_info.stat_handle,
																		FS_STYLE_FIELD,
																		FS_CALC_CURRENT,
																		DNS_STATIS_INFO[i].str);

		if(g_dns_proto_info.fild_id[DNS_STATIS_INFO[i].id] == -1)
		{
			MESA_handle_runtime_log(g_dns_proto_info.logger, RLOG_LV_FATAL, "DNS_INIT",
								"register field_id failled and str: %s", DNS_STATIS_INFO[i].str);
			return -1;
		}
	}

	FS_start(g_dns_proto_info.stat_handle);
	
	return PROTID_DNS;
}


/****************************************************************************
??????:DNS_DESTRORY()
?????DNS???ж???????????????????
??????
???????
*****************************************************************************/
void  DNS_DESTROY()
{
	printf("Hello! This is dns.so PROT_DESTORY, but i am not complete!!!\n");
}


void PROT_FUNSTAT(long long protflag)
{
	int i = 0;

	if(0==protflag)
	{
		return;
	}
	
	pthread_mutex_init(&dns_lock, NULL);
	pthread_mutex_lock(&dns_lock);

	dns_register_flag = protflag;

	for(i = 0; i < (int)sizeof(dns_register_flag)*8; i++)
	{
		if((dns_register_flag>>i)&0x01)
		{
			dns_register_flag_num++;
		}
	}

	pthread_mutex_unlock(&dns_lock);
	return;
}

void GET_PLUGID(unsigned short plugid)
{
	dns_plugid = plugid;
}

static long long get_flag_id(const char *flag_str)
{
	int i = 0;

	for(i = 0; DNS_FLAG_ID[i].str != NULL; i++)
	{
		if((strncasecmp(DNS_FLAG_ID[i].str, flag_str, strlen(DNS_FLAG_ID[i].str)) == 0)
		 && (strlen(DNS_FLAG_ID[i].str) == strlen(flag_str)))
		{
			return DNS_FLAG_ID[i].id;
		} 
	}

	printf("dns.so: error! Invalid DNS FLAG:%s\n", flag_str);

	return 0;
}

long long FLAG_CHANGE(char* raw_flag_str)
{
	long long dns_portflag = 0;
	char *save_ptr;
	const char *delim = " \t,";
	char *section;
	char *flag_str, *parse_ptr;

	if(NULL == raw_flag_str || '\0' == *raw_flag_str){
		return 0;
	}

	flag_str = (char *)malloc(strlen(raw_flag_str)+1);//add EOF
	memcpy(flag_str, raw_flag_str, strlen(raw_flag_str)+1);//add EOF

	parse_ptr = flag_str;
	while(((section = strtok_r(parse_ptr, delim, &save_ptr)) != NULL))
	{
		dns_portflag |= get_flag_id(section);
		parse_ptr = NULL;
	}

	free(flag_str);
	
	return dns_portflag;
}

//TODO：暂未实现
void FLAG_PROT_FUNSTAT (long long protflag)
{
  return ;
}
