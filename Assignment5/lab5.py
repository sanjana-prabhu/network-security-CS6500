import argparse

rule_dict = {}

def check_valid_rules(rulefilename):

    f_r = open(rulefilename, 'r')
    num = 0
    total_count = 0
    value_list = []
    for line in f_r:

        line = line.strip('\n')

        if line=='BEGIN':
            value_list = []

        if line[:3]=='NUM':
            num = int(line[5:])

        if line[:6]=='SRC IP':
            value_list.append(line[13:])

        if line[:7]=='DEST IP':
            value_list.append(line[14:])

        if line[:8]=='SRC PORT':
            port_nums = line[10:].split('-')
            port_num_1 = int(port_nums[0])
            port_num_2 = int(port_nums[1])
            if (port_num_1>=0 and port_num_2>=0 and port_num_1<=65535 and port_num_2<=65535 and port_num_1<=port_num_2):
                pass
            else:
                num = -1
            value_list.append(port_num_1)
            value_list.append(port_num_2)

        if line[:9]=='DEST PORT':
            port_nums = line[11:].split('-')
            port_num_1 = int(port_nums[0])
            port_num_2 = int(port_nums[1])
            if (port_num_1>=0 and port_num_2>=0 and port_num_1<=65535 and port_num_2<=65535 and port_num_1<=port_num_2):
                pass
            else:
                num = -1
            value_list.append(port_num_1)
            value_list.append(port_num_2)

        if line[:8]=='PROTOCOL':
            value_list.append(line[10:])

        if line[:4]=='DATA':
            value_list.append(line[6:])

        if line=='END':
            temp_dict = {}
            temp_dict[num] = value_list
            rule_dict.update(temp_dict)
            total_count = total_count + 1

    try:
        rule_dict.pop(-1)
    except KeyError:
        pass
    count = len(list(rule_dict.keys()))
    print("A total of", total_count, "rules were read and", count, "valid rules were stored.")

def num2bits(num):

    return "{0:b}".format(int(num))

def check_ip_match(packet_ip, rule_ip):

    bits2len_dict = {8:3, 20:8, 12:6}
    if rule_ip=='0.0.0.0/0':
        return 1
    index = rule_ip.index('/')
    rule_len = int(rule_ip[index+1:])
    full_fields = int(rule_len/8)
    remaining_bits = rule_len%8
    rule_ip_bytes = rule_ip[:index].split('.')
    packet_ip_bytes = packet_ip.split('.')
    check = []
    for i in range(full_fields):
        if int(rule_ip_bytes[i])==int(packet_ip_bytes[i]):
            check.append(1)
        else:
            check.append(0)
    rule_ip_bits = num2bits(int(rule_ip_bytes[full_fields]))
    packet_ip_bits = num2bits(int(packet_ip_bytes[full_fields]))
    if rule_ip_bits[:remaining_bits]==packet_ip_bits[:remaining_bits]:
        if sum(check)==len(check):
            return 1
    else:
        return 0

def check_match(packet_list):

    matching_rule_list = []
    for key, value in rule_dict.items():
        src_ip_match = 0
        dest_ip_match = 0
        src_port_match = 0
        dest_port_match = 0
        protocol_match = 0
        data_check = 0

        if check_ip_match(packet_list[0], value[0]):
            src_ip_match = 1
        if check_ip_match(packet_list[1], value[1]):
            dest_ip_match = 1
        if int(packet_list[2])>=int(value[2]) and int(packet_list[2])<=int(value[3]):
            src_port_match = 1
        if int(value[2])==0 and int(value[3])==0:
            src_port_match = 1
        if int(packet_list[3])>=int(value[4]) and int(packet_list[3])<=int(value[5]):
            dest_port_match = 1
        if int(value[4])==0 and int(value[5])==0:
            dest_port_match = 1
        if packet_list[4]==value[6]:
            protocol_match = 1
        if packet_list[5].count(value[7]):
            data_check = 1
        sum_check = src_ip_match+dest_ip_match+src_port_match+dest_port_match+protocol_match+data_check
        if sum_check==6:
            matching_rule_list.append(key)

    return matching_rule_list

def check_packet_match(pktfilename):
   
    f_p = open(pktfilename, 'r')
    num = 0
    total_count = 0
    value_list = []
    for line in f_p:

        line = line.strip('\n')

        if line=='BEGIN':
            value_list = []

        if line[:3]=='NUM':
            num = int(line[5:])
            packet_id = num

        if line[:6]=='SRC IP':
            value_list.append(line[13:])

        if line[:7]=='DEST IP':
            value_list.append(line[14:])

        if line[:8]=='SRC PORT':
            port_num = int(line[10:])
            if port_num<0 or port_num>65535:
                num = -1
            value_list.append(port_num)

        if line[:9]=='DEST PORT':
            port_num = int(line[11:])
            if port_num<0 or port_num>65535:
                num = -1
            value_list.append(port_num)

        if line[:8]=='PROTOCOL':
            value_list.append(line[10:])

        if line[:4]=='DATA':
            value_list.append(line[6:])

        if line=='END':
            packet_dict = {}
            if num==-1:
                print("Packet", packet_id, "is invalid.")
            else:
                packet_list = value_list
                matching_rule_list = check_match(packet_list)
                print("Packet", packet_id, "matches rule number(s):",matching_rule_list)
            total_count = total_count + 1


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(type=str, dest='rulefilename')
    parser.add_argument(type=str, dest='pktfilename')
    args = parser.parse_args()

    check_valid_rules(args.rulefilename)
    check_packet_match(args.pktfilename)

if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise