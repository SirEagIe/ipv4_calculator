import re

ipv4_prefix_regex1=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}"
ipv4_prefix_regex2=r"([1-9][0-9]?|1[0-9][0-9]|(2[0-1][0-9]|22[0-3]))(\.([1-9]?[0-9]|1[0-9][0-9]|(2[0-4][0-9]|25[0-5]))){3}\/(3[0-2]|[1-2][0-9]|[1-9])"

class BinaryTree:
    """
    Класс ноды бинарного дерева.
    Два основных аттрибута ноды: prefix (сеть в формате CIDR) и data (произвольная метка префикса).
    Порядковый слой дерева соответсвует длине маски префикса.
    """
    def __init__(self, prefix, data):
        octets = prefix.split("/")[0].split(".")
        self.prefix = prefix
        self.address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        self.netmask = int(prefix.split("/")[1])
        self.data = [data] if data else []
        self.left = None
        self.right = None

    def set_prefix_data(self, prefix, data):
        """
        Устанавливает значение prefix-data путём добавления в дерево новой ноды.
        При поиске ноды производит спуск с корня и создаёт на каждом шаге две дочерние ноды с пустым полем data, в случае их отсутствия.
        В итоге нахождения ноды добавляет метку в поле data, либо создаёт ноду в случае её отсутствия.
        """
        if (prefix is None) or (data is None):
            return None
        netmask = int(prefix.split("/")[1])
        netmask_bits = (0xffffffff - (1 << (32 - int(netmask))) + 1)
        octets = prefix.split("/")[0].split(".")     
        address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        if ((netmask_bits & address) == address):
            node = self
            for i in range(1, netmask + 1):
                direction = ((address >> (32 - i)) & 0x1)
                if node.left is None:
                    children_left_address = node.address
                    children_left_prefix = str(int((children_left_address >> 24) & 0x000000ff)) + "." + str(int((children_left_address >> 16) & 0x000000ff))\
                        + "." + str(int((children_left_address >> 8) & 0x000000ff)) + "." + str(int(children_left_address & 0x000000ff)) + "/" + str(i)
                    node.left = BinaryTree(children_left_prefix, "")
                if node.right is None:
                    children_right_address = node.address | (0x1 << (32 - i))
                    children_right_prefix = str(int((children_right_address >> 24) & 0x000000ff)) + "." + str(int((children_right_address >> 16) & 0x000000ff))\
                        + "." + str(int((children_right_address >> 8) & 0x000000ff)) + "." + str(int(children_right_address & 0x000000ff)) + "/" + str(i)
                    node.right = BinaryTree(children_right_prefix, "")
                if (direction == 0):
                    node = node.left
                else:
                    node = node.right
            node.data.append(data)
        else:
            raise Exception("Invalid prefix/prefix length: " + prefix + ". All host bits should be 0.")

    def get_prefix_data(self, prefix):
        """
        Производит поиск ноды в дереве по префиксу и возвращает данные о искомой ноде.
        Формат возвращаемых данных:
        [префикс, адрес_в_двоичном_виде, длина_маски, [метка, ...]]
        """
        if (prefix is None):
            return None
        netmask = int(prefix.split("/")[1])
        octets = prefix.split("/")[0].split(".")     
        address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        
        prefix_mask_bin = (0xffffffff - (1 << (32 - int(netmask))) + 1)
        address = address & prefix_mask_bin
        
        node = self
        for i in range(1, netmask + 1):
            direction = ((address >> (32 - i)) & 0x1)
            if (direction == 0):
                if node.left is None:
                    return None
                else:
                    node = node.left
            else:
                if node.right is None:
                    return None
                else:
                    node = node.right
        return([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])

    def get_prefix_data2(self, prefix):
        """
        Производит поиск ноды в дереве по префиксу и возвращает данные о искомой ноде,
        либо, если искомая нода не определена, возвращает данные префикса с метками из ближайшей к ней родительской ноды,
        либо, если у искомой ноды не заданы метки, возвращает все дочерние ноды, имеющие метки.
        Формат возвращаемых данных:
        [[префикс, адрес_в_двоичном_виде, длина_маски, [метка, ...]], ...]
        """
        if (prefix is None):
            return None
        netmask = int(prefix.split("/")[1])
        octets = prefix.split("/")[0].split(".")     
        address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        prefix_mask_bin = (0xffffffff - (1 << (32 - int(netmask))) + 1)
        address = address & prefix_mask_bin
        node = self
        for i in range(1, netmask + 1):
            direction = ((address >> (32 - i)) & 0x1)
            if (direction == 0):
                if node.left is None:
                    return([[prefix, "{:032b}".format(address), netmask, node.data]])
                else:
                    node = node.left
            else:
                if node.right is None:
                    return([[node.prefix, "{:032b}".format(node.address), node.netmask, node.data]])
                else:
                    node = node.right
        if not node.data:
            def get_subtree_data(node):
                result = []
                if node.left and node.left.data:
                    result.append([node.left.prefix, "{:032b}".format(node.left.address), node.left.netmask, node.left.data])
                if node.right and node.right.data:
                    result.append([node.right.prefix, "{:032b}".format(node.right.address), node.right.netmask, node.right.data])
                if not node.left and not node.right:
                    return []
                return result + get_subtree_data(node.left) + get_subtree_data(node.right)
            return(get_subtree_data(node))
        else:
            return([[node.prefix, "{:032b}".format(node.address), node.netmask, node.data]])


    def get_prefix_data3(self, prefix):
        """
        Производит поиск ноды в дереве по префиксу и возвращает данные о искомой ноде,
        ноде, по которым проходился цикл во время поиска, и все дочерние ноды с метками.
        Формат возвращаемых данных:
        [[префикс, адрес_в_двоичном_виде, длина_маски, [метка, ...]], ...]
        """
        if (prefix is None):
            return None
        netmask = int(prefix.split("/")[1])
        octets = prefix.split("/")[0].split(".")     
        address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        prefix_mask_bin = (0xffffffff - (1 << (32 - int(netmask))) + 1)
        address = address & prefix_mask_bin
        node = self
        result = []
        for i in range(1, netmask + 1):
            if node.data:
                result.append([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])
            direction = ((address >> (32 - i)) & 0x1)
            if (direction == 0):
                if node.left is None:
                    break
                else:
                    node = node.left
            else:
                if node.right is None:
                    break
                else:
                    node = node.right

        if node.data:
            result.append([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])

        def get_subtree_data(node):
            res = []
            if node.left and node.left.data:
                res.append([node.left.prefix, "{:032b}".format(node.left.address), node.left.netmask, node.left.data])
            if node.right and node.right.data:
                res.append([node.right.prefix, "{:032b}".format(node.right.address), node.right.netmask, node.right.data])
            if not node.left and not node.right:
                return []
            return res + get_subtree_data(node.left) + get_subtree_data(node.right)
        return(result + get_subtree_data(node))

    def get_prefix_data4(self, prefix):
        """
        Производит поиск ноды в дереве по префиксу и возвращает данные о искомой ноде,
        ноде, по которым проходился цикл во время поиска, и все дочерние ноды с метками + дочерние листья без меток.
        Формат возвращаемых данных:
        [[префикс, адрес_в_двоичном_виде, длина_маски, [метка, ...]], ...]
        """
        if (prefix is None):
            return None
        netmask = int(prefix.split("/")[1])
        octets = prefix.split("/")[0].split(".")     
        address = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        prefix_mask_bin = (0xffffffff - (1 << (32 - int(netmask))) + 1)
        address = address & prefix_mask_bin
        node = self
        result = []
        print(netmask)
        for i in range(1, netmask + 1):
            print([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])
            if node.data:
                result.append([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])
            direction = ((address >> (32 - i)) & 0x1)
            if (direction == 0):
                if node.left is None:
                    break
                else:
                    node = node.left
            else:
                if node.right is None:
                    break
                else:
                    node = node.right

        if node.data:
            result.append([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])

        def get_subtree_data(node):
            res = []
            if node.left and node.left.data:
                res.append([node.left.prefix, "{:032b}".format(node.left.address), node.left.netmask, node.left.data])
            if node.right and node.right.data:
                res.append([node.right.prefix, "{:032b}".format(node.right.address), node.right.netmask, node.right.data])
            if not node.left and not node.right and not node.data:
                return [[node.prefix, "{:032b}".format(node.address), node.netmask, node.data]]
            elif not node.left and not node.right:
                return []
            return res + get_subtree_data(node.left) + get_subtree_data(node.right)
        return(result + get_subtree_data(node))
    

    def check_subtree_data(self):
        root = self
        if root is None:
            return(0)
        queue = []
        if root.left is not None:
            queue.append(root.left)
        if root.right is not None:
            queue.append(root.right)
        while len(queue) > 0:
            cur_node = queue.pop(0)
            if (cur_node.data != ""):
                print("  Prefix " + root.prefix + " overlaps with prefix " + cur_node.prefix)
                return (1)
            else:
                if cur_node.left is not None:
                    queue.append(cur_node.left)
                if cur_node.right is not None:
                    queue.append(cur_node.right)
        return(0)

    def remove_data_overlay(self):
        root = self
        if root is None:
            return
        queue = [root]
        while len(queue) > 0:
            cur_node = queue.pop(0)
            if ((cur_node.data != "") and ((cur_node.check_subtree_data() == 1))):
                if cur_node.left is not None:
                    queue.append(cur_node.left)
                    if cur_node.left.data == "": cur_node.left.data = cur_node.data
                if cur_node.right is not None:
                    queue.append(cur_node.right)
                    if cur_node.right.data == "": cur_node.right.data = cur_node.data
                print("  Splitting prefix: " + str(cur_node.prefix) + " into prefixes: " + str(cur_node.left.prefix) + ", " + str(cur_node.right.prefix) + " with data \"" + str(cur_node.data) + "\"")
                cur_node.data = ""
            else:
                if cur_node.left is not None:
                    queue.append(cur_node.left)
                if cur_node.right is not None:
                    queue.append(cur_node.right)

    def aggregate_data(self):
        root = self
        if root is None:
            return
        self.aggregate_data2(root)
        
    def aggregate_data2(self, node):
        if node is None:
            return
        self.aggregate_data2(node.left)
        if ((node.left is not None) and (node.right is not None)):
            if ((node.left.data != "") and (node.left.data == node.right.data) and (node.data == "")):
                node.data = node.left.data
                print("  Combining prefixes: "  + str(node.left.prefix) + ", " + str(node.right.prefix) + " into prefix: " + str(node.prefix) + " with data \"" + str(node.data) + "\"")
                node.left.data = ""
                node.right.data = ""
        self.aggregate_data2(node.right)

    def export_all_prefixes(self):
        root = self
        if root is None:
            return
        output = []

        def export_all_prefixes2(node):
            if node is None:
                return
            export_all_prefixes2(node.left)
            if node.data != "":
                output.append([node.prefix, "{:032b}".format(node.address), node.netmask, node.data])
            export_all_prefixes2(node.right)

        export_all_prefixes2(root)
        return output


def optimize_prefixes(prefixes):
    """
    Производит оптимизацию списка префиксов
    (убирает пересечения и максимально объединяет префиксы)
    """
    ipv4_prefix_root = BinaryTree("0.0.0.0/0", "")
    for prefix in prefixes:
        ipv4_prefix_root.set_prefix_data(prefix, 1)
    def union_tree(node):
        if node.left:
            union_tree(node.left)
        if node.right:
            union_tree(node.right)
        if node.left and node.left.data and node.right and node.right.data:
            node.data = 1
    union_tree(ipv4_prefix_root)
    def get_tree(node):
        if node.data:
            return [node.prefix]
        else:
            return (get_tree(node.left) if node.left else []) + \
                (get_tree(node.right) if node.right else [])
    return(get_tree(ipv4_prefix_root))


def search_prefix(datas, prefix):
    """
    Производит поиск префикса в списке [(метка, [префиксы]), ...]
    На выходе: найденные метки; найденные префиксы; не найденные префиксы
    """
    datas_recombined = []
    for data in datas:
        if re.match(ipv4_prefix_regex1, data[1]):
            datas_recombined += zip(data[1].split(', '), [data[0]]*len(data[1].split(',')))
    ipv4_prefix_root = BinaryTree("0.0.0.0/0", "")
    for data in datas_recombined:
        ipv4_prefix_root.set_prefix_data(data[0], data[1])

    searched = ipv4_prefix_root.get_prefix_data3(prefix)
    datas_result = []
    for res in searched:
        if res[3] not in datas_result:
            datas_result += res[3]
    datas_result = list(set(datas_result))

    return (
        datas_result,
        list(set([res[0] for res in searched if res[3]])),
        optimize_prefixes([res[0] for res in searched if not res[3]])
    )

def normalize_prefix(prefix):
    octets = prefix.split("/")[0].split(".")
    prefix_net_bin = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
    netmask = int(prefix.split("/")[1])
    prefix_mask_bin = (0xffffffff - (1 << (32 - int(netmask))) + 1)
    prefix_net_bin = (prefix_net_bin & prefix_mask_bin)
    return str(int((prefix_net_bin >> 24) & 0x000000ff)) + "." + str(int((prefix_net_bin >> 16) & 0x000000ff)) + "." + str(int((prefix_net_bin >> 8) & 0x000000ff)) + "." + str(int(prefix_net_bin & 0x000000ff)) + "/" + str(netmask)

def intersection(net_1, net_2):
    ipv4_cidr_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$'
    ipv4_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_regex, net_1):
        net_1 += '/32'
    if re.match(ipv4_regex, net_2):
        net_2 += '/32'
    if re.match(ipv4_cidr_regex, net_1) and re.match(ipv4_cidr_regex, net_2):
        net_1_octets, net_1_mask = list(map(lambda x: int(x), net_1.split('/')[0].split('.'))), int(net_1.split('/')[1])
        net_2_octets, net_2_mask = list(map(lambda x: int(x), net_2.split('/')[0].split('.'))), int(net_2.split('/')[1])
        net_1_octets = net_1_octets[0] << 24 | net_1_octets[1] << 16 | net_1_octets[2] << 8 | net_1_octets[3]
        net_2_octets = net_2_octets[0] << 24 | net_2_octets[1] << 16 | net_2_octets[2] << 8 | net_2_octets[3]
        net_1_mask = 0xffffffff - (1 << (32 - net_1_mask)) + 1
        net_2_mask = 0xffffffff - (1 << (32 - net_2_mask)) + 1
        if net_1_octets & min(net_1_mask, net_2_mask) == net_2_octets & min(net_1_mask, net_2_mask):
            return net_1 if net_1_mask > net_2_mask else net_2
        else:
            return None
    return None
