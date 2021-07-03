#!/usr/bin/env python3
import argparse
import collections
import dataclasses
import enum
import logging
import struct
import sys
import typing

try:
    import graphviz
except ImportError:
    pass

l = logging.getLogger("assembler")

Opcode = collections.namedtuple('Opcode', ['opcode', 'num_inputs', 'repr'])
Instruction = collections.namedtuple('Instruction', [
                                     'opcode', 'destination_1', 'destination_2', 'literal_1', 'literal_2'])
Destination = collections.namedtuple('Destination', ['node', 'input'])


@dataclasses.dataclass
class Node:
    opcode: Opcode
    id: int
    input_1: int = None
    input_2: int = None
    destination_1: Destination = None
    destination_2: Destination = None
    optimizable: bool = False

    def __repr__(self):
        input_1_text = f"{self.input_1}" if self.input_1 is not None else ""
        input_2_text = f" {self.input_2}" if self.input_2 is not None else ""
        destination = ""
        if self.destination_1 is not None:
            destination += f"{self.destination_1.node.id}"
        if self.destination_2 is not None:
            destination += f", {self.destination_2.node.id}"
        return f"{self.id}: {self.opcode.repr} {input_1_text}{input_2_text} -> {destination}"

    def __eq__(self, other):
        if type(other) is type(self):
            return other.id == self.id
        else:
            return False

    def __hash__(self):
        return hash(self.id)


@dataclasses.dataclass
class Graph:
    nodes: typing.List[Node] = dataclasses.field(default_factory=list)
    labels: typing.Dict[str, Node] = dataclasses.field(default_factory=dict)
    external_references: typing.Dict[str, typing.List[Node]] = dataclasses.field(default_factory=lambda: collections.defaultdict(list))
    exports: typing.Set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass
class DestinationToUpdate:
    instruction_num: int
    is_first_destination: bool = False
    is_second_destination: bool = False
    is_first_literal: bool = False
    is_second_literal: bool = False

    def combine_flags(self):
        to_return = 0
        if self.is_first_destination:
            to_return |= 1
        if self.is_second_destination:
            to_return |= 0x2
        if self.is_first_literal:
            to_return |= 0x4
        if self.is_second_literal:
            to_return |= 0x8
        return to_return

    def to_binary(self):
        return struct.pack('<IBxxx',
                           self.instruction_num,
                           self.combine_flags()
                           )

    @staticmethod
    def from_binary(f):
        instruction_num, flags = struct.unpack('<IBxxx', f.read(8))
        return DestinationToUpdate(instruction_num, flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 8 != 0)


@dataclasses.dataclass
class ExternalSymbol:
    destination_to_update: DestinationToUpdate
    name: bytes

    def to_binary(self):
        to_return = self.destination_to_update.to_binary()
        to_return += struct.pack('<256s', self.name)
        return to_return

    @staticmethod
    def from_binary(f: typing.BinaryIO):
        destination_to_update = DestinationUpdate.from_binary(f)
        name = struct.unpack('<256s', f.read(256))
        return ExternalSymbol(destination_to_update, name)


@dataclasses.dataclass
class ExportedSymbol:
    destination: int
    name: bytes

    def to_binary(self):
        return struct.pack('<I256s',
                           self.destination,
                           self.name)

    @staticmethod
    def from_binary(f: typing.BinaryIO):
        return ExportedSymbol(*struct.unpack('<I256s', f.read(260)))


_OPCODE_LIST = [
    # OUT is a special opcode that represents an output address of the
    # machine, not an actual instruction (which is why we give it opcode -1
    Opcode(-1, 1, 'OUTD'),
    Opcode(-2, 1, 'OUTS'),
    Opcode(0, 2, 'ADD'),
    Opcode(1, 2, 'SUB'),
    Opcode(2, 2, 'BRR'),
    Opcode(3, 2, 'LT'),
    Opcode(4, 2, 'EQ'),
    Opcode(5, 1, 'DUP'),
    Opcode(6, 1, 'NEG'),
    Opcode(7, 2, 'MER'),
    Opcode(8, 1, 'NTG'),
    Opcode(9, 1, 'ITG'),
    Opcode(10, 2, 'GT'),
    Opcode(11, 2, 'SIL'),
    Opcode(12, 2, 'CTG'),
    Opcode(13, 2, 'RTD'),
    Opcode(14, 1, 'ETG'),
    Opcode(15, 2, 'MUL'),
    Opcode(16, 2, 'XOR'),
    Opcode(17, 2, 'AND'),
    Opcode(18, 2, 'OR'),
    Opcode(19, 2, 'SHL'),
    Opcode(20, 2, 'SHR'),
    Opcode(21, 2, 'NEQ'),
    Opcode(22, 2, 'OPN'),
    Opcode(23, 1, 'RED'),
    Opcode(24, 2, 'WRT'),
    Opcode(25, 1, 'CLS'),
    Opcode(26, 2, 'GTE'),
    Opcode(27, 2, 'LTE'),
    Opcode(28, 1, 'HLT'),
    Opcode(29, 2, 'LOD'),
    Opcode(30, 1, 'LS'),
    Opcode(31, 2, 'SDF'),
    Opcode(32, 1, 'ULK'),
    Opcode(33, 2, 'LSK'),
    Opcode(34, 1, 'RND'),
]


OPCODES = {o.repr: o for o in _OPCODE_LIST}

SPECIAL_OPCODES = [OPCODES['OUTD'], OPCODES['OUTS']]
SPECIAL_OPCODES_NAMES = [o.repr for o in SPECIAL_OPCODES]


def create_destination(addr, input, matching):
    return ((((addr << 1) ^ input) << 3) ^ matching) & (2**32-1)


MATCHING_ONE = 0
MATCHING_BOTH = 1
MATCHING_ANY = 2

INPUT_ONE = 0
INPUT_TWO = 1

BOTH_OUTPUT_MARKER = 1
ONE_OUTPUT_MARKER = 0

OUTPUTD_DESTINATION = create_destination(
    ((1 << 28)-1), INPUT_ONE, MATCHING_ONE)
OUTPUTS_DESTINATION = create_destination(
    ((1 << 28)-2), INPUT_ONE, MATCHING_ONE)
REGISTER_INPUT_HANDLER_DESTINATION = create_destination(
    ((1 << 28)-3), INPUT_ONE, MATCHING_ONE)
DEREGISTER_INPUT_HANDLER_DESTINATION = create_destination(
    ((1 << 28)-4), INPUT_ONE, MATCHING_ONE)
DEV_NULL_DESTINATION = create_destination(
    ((1 << 28)-5), INPUT_ONE, MATCHING_ONE)

INPUTS = [('input_1', INPUT_ONE), ('input_2', INPUT_TWO)]


class InstructionLiteralType(enum.Enum):
    NONE = 0
    ONE = 1
    TWO = 2


def serialize_instructions(instructions):
    to_return = b""
    for inst in instructions:
        marker = BOTH_OUTPUT_MARKER if inst.destination_2 else ONE_OUTPUT_MARKER
        instruction_literal = InstructionLiteralType.NONE.value
        if inst.literal_1 is not None and inst.literal_2 is not None:
            instruction_literal = InstructionLiteralType.TWO.value
        elif inst.literal_1 is not None or inst.literal_2 is not None:
            instruction_literal = InstructionLiteralType.ONE.value

        to_return += struct.pack('<IIIBxxxqqIxxxx',
                                 inst.opcode.opcode,
                                 inst.destination_1 if inst.destination_1 is not None else DEV_NULL_DESTINATION,
                                 inst.destination_2 if inst.destination_2 is not None else DEV_NULL_DESTINATION,
                                 marker,
                                 inst.literal_1 or 0,
                                 inst.literal_2 or 0,
                                 instruction_literal,
                                 )
    l.info(f"num of instructions: {len(instructions)}")
    l.info(f"size of instructions: {len(to_return)}")
    return to_return


def unserialize_instructions(f):
    to_return = f.read()
    FORMAT = '<IIIBxxxqqIxxxx'
    size = struct.calcsize(FORMAT)
    num = len(to_return) // size
    instructions = []
    for i in range(num):
        start = i * size
        opcode,\
            destination_1,\
            destination_2,\
            marker,\
            literal_1,\
            literal_2,\
            instruction_literal =\
            struct.unpack_from(FORMAT,
                               to_return[start:start + size])

        destination_2 = None if marker == BOTH_OUTPUT_MARKER else destination_2
        if instruction_literal == InstructionLiteralType.NONE.value:
            literal_1 = literal_2 = None
        elif instruction_literal != InstructionLiteralType.TWO.value:
            assert(instruction_literal == InstructionLiteralType.ONE.value)
            if literal_1 == 0:
                literal_1 = None
            else:
                literal_2 = None
        inst = Instruction(opcode, destination_1, destination_2, literal_1, literal_2)
        instructions.append(inst)
        print(inst)
    l.info(f"num of instructions: {len(instructions)}")
    l.info(f"size of instructions: {len(to_return)}")
    return instructions


def _(to_return: typing.BinaryIO, expected: bytes):
    assert to_return.read(len(expected)) == expected


def generate_header(f: typing.BinaryIO) -> (typing.List[DestinationToUpdate],
                                            typing.List[DestinationToUpdate],
                                            typing.List[ExternalSymbol],
                                            typing.List[ExportedSymbol]):
    magic_bytes = b"sephiALD"

    _(f, magic_bytes)
    num_constant, num_to_fix, num_external_ref, num_exported = struct.unpack(
        '<HHHH', f.read(8))
    constants = [DestinationToUpdate.from_binary(
        f) for i in range(num_constant)]
    labels = [DestinationToUpdate.from_binary(f) for i in range(num_to_fix)]
    external_references = [ExternalSymbol.from_binary(
        f) for i in range(num_external_ref)]
    exported = [ExportedSymbol.from_binary(f) for i in range(num_exported)]

    return constants, labels, external_references, exported


def node_to_instruction(node: Node) -> typing.Optional[Instruction]:
    """
    Turn a node in the IR graph into an instruction. Some aspects
    can't be decided now (such as the destination address), they'll be
    done later.

    If the node represents a special instruction that does not exist
    (OUT as a memory location, for instance), then this will return None.
    """

    if node.opcode in SPECIAL_OPCODES:
        return None
    return Instruction(node.opcode, None, None, node.input_1, node.input_2)


def graph_to_instructions(graph: Graph) -> typing.Tuple[typing.List[Instruction],
                                                        typing.List[DestinationToUpdate],
                                                        typing.List[DestinationToUpdate],
                                                        typing.List[ExternalSymbol],
                                                        typing.List[ExportedSymbol]]:
    to_return = []
    constants = []
    labels = []
    external_references = []
    exports = []

    nodes_to_extern = {}
    for extern, nodes in graph.external_references.items():
        for node in nodes:
            nodes_to_extern[node] = extern

    node_to_idx = {}

    to_visit = collections.deque()
    for node in graph.nodes:
        inst = node_to_instruction(node)
        l.debug(f"node={node} to inst={inst}")
        if inst:
            node_to_idx[node] = len(to_return)
            to_return.append(inst)
            to_visit.append(node)

    while len(to_visit) != 0:
        node = to_visit.popleft()
        assert(not node.opcode in SPECIAL_OPCODES)
        l.debug(f"visiting node={node}")

        inst = to_return[node_to_idx[node]]

        # Only input 1 should have a label at this point
        assert (not node.input_2 in graph.labels)

        if node.input_1 in graph.labels:
            target = graph.labels[node.input_1]
            l.debug(f"node={node} has a label={node.input_1} as input which is target={target}")

            # label targets have one input (usually a DUP)
            input_addr = create_destination(node_to_idx[target],
                                            INPUT_ONE,
                                            MATCHING_ONE)

            inst = inst._replace(**{"literal_1": input_addr})
            labels.append(DestinationToUpdate(node_to_idx[node],
                                              is_first_literal=True))
            l.debug(f"updated inst={inst}")
            to_return[node_to_idx[node]] = inst

        for dest in ['destination_1', 'destination_2']:
            destination = getattr(node, dest)
            if destination is None:
                continue
            destination_node = destination.node
            if destination_node.opcode == OPCODES['OUTD']:
                l.debug(f"destination is special output instruction")
                inst = inst._replace(**{dest: OUTPUTD_DESTINATION})
                constants.append(DestinationToUpdate(node_to_idx[node],
                                                     is_first_destination=(
                                                         dest == 'destination_1'),
                                                     is_second_destination=(
                                                         dest == 'destination_2'),
                                                     ))
            elif destination_node.opcode == OPCODES['OUTS']:
                l.debug(f"destination is special output instruction")
                inst = inst._replace(**{dest: OUTPUTS_DESTINATION})
                constants.append(DestinationToUpdate(node_to_idx[node],
                                                     is_first_destination=(
                                                         dest == 'destination_1'),
                                                     is_second_destination=(
                                                         dest == 'destination_2'),
                                                     ))
            else:
                if destination_node in node_to_idx:
                    l.debug(f"Already seen destination_node={destination_node}")
                    dest_inst = to_return[node_to_idx[destination_node]]
                else:
                    dest_inst = node_to_instruction(destination_node)
                    node_to_idx[destination_node] = len(to_return)
                    to_return.append(dest_inst)
                    to_visit.append(destination_node)
                    l.debug(f"Adding destination_node={destination_node} dest_inst={dest_inst} to visit queue")

                assert(dest_inst)
                which_input = destination.input

                matching = None
                if destination_node.opcode.num_inputs == 1:
                    matching = MATCHING_ONE
                elif destination_node.opcode.num_inputs == 2:
                    # if there's two literals, it can't be a destination
                    assert(
                        not (destination_node.input_1 and destination_node.input_2))
                    if destination_node.opcode == OPCODES['MER']:
                        matching = MATCHING_ANY
                    elif destination_node.input_1 is not None:
                        matching = MATCHING_ONE
                    else:
                        matching = MATCHING_BOTH
                else:
                    assert(False)

                dest_addr = create_destination(node_to_idx[destination_node],
                                               which_input,
                                               matching)
                inst = inst._replace(**{dest: dest_addr})

            l.debug(f"updated inst={inst}")
            to_return[node_to_idx[node]] = inst

        if node in nodes_to_extern:
            extern = nodes_to_extern[node]
            external_references.append(ExternalSymbol(DestinationToUpdate(node_to_idx[node],
                                                                          is_first_destination=True),
                                                      extern.encode()))

    # exporting a defined label
    for export in graph.exports:
        target_node = graph.labels[export]
        # label targets have one input (usually a DUP)
        input_addr = create_destination(node_to_idx[target_node],
                                        INPUT_ONE,
                                        MATCHING_ONE)
        exports.append(ExportedSymbol(input_addr, export.encode()))

    return to_return, constants, labels, external_references, exports


def parse_arg(arg: str):
    try:
        val = int(arg, base=10)
        return val
    except ValueError:
        pass

    if arg.lower().startswith('0x'):
        try:
            val = int(arg, base=16)
            return val
        except ValueError:
            pass

    return arg


def parse_create_ir_graph(input: typing.TextIO) -> Graph:
    to_return = Graph()
    variables = collections.defaultdict(list)
    node_num = 0

    label = None
    i = 0
    for line in input:
        i += 1
        line = line.strip()
        l.debug(f"Analyzing line {i}")
        if (not line) or line.startswith("#"):
            continue

        args = line.split()
        l.debug(f"args={args}")
        if len(args) == 1:
            the_label = args[0]
            if not the_label.endswith(':'):
                l.error(f"Label on line {i} does not end with a colon ':'")
                sys.exit(-1)

            if label:
                l.error(f"Label on line {i} but a label is already defined.")
                sys.exit(-1)

            label = the_label.rstrip(':')

            if label in to_return.labels:
                l.error(f"Label on line {i} is {label}, however {label} is already defined")
                sys.exit(-1)

            l.debug(f"Next instruction's label will be {label}")

        elif args[0].upper() == 'EXPORT':
            exported = args[1]
            if not exported in to_return.labels:
                l.error(f"exported symbol {exported} is not defined in the labels {to_return.labels.keys()}")
                sys.exit(-1)
            l.debug(f"found export label {args[1]}")
            to_return.exports.add(exported)
            pass

        elif args[0].upper() == 'EXTERN':
            to_return.external_references[args[1]] = list()
            l.debug(f"found external reference {args[1]}")

        elif args[1] == "=":
            if not (len(args) == 5 or len(args) == 4):
                l.error(f"Line {i} malformed")
                sys.exit(-1)

            operation = args[2].upper()
            if not operation in OPCODES:
                l.error(f"{operation} not supported on line {i}")
                sys.exit(-1)

            opcode = OPCODES[operation]
            # Try to see if the arguments are literals
            num_arguments = opcode.num_inputs

            first_arg = args[3]
            input_1 = parse_arg(first_arg)

            input_2 = None
            if num_arguments == 2:
                second_arg = args[4]
                input_2 = parse_arg(second_arg)

            if isinstance(input_1, int) and isinstance(input_2, str):
                l.error(f"literals must only be on the second input. {input_2} is a variable and {input_1} is a literal on line {i}")
                sys.exit(-1)

            # MERge instructions can't have any literals
            if opcode == OPCODES['MER']:
                if isinstance(input_1, int) or isinstance(input_2, int):
                    l.error(f"MER instructions cannot have a literal argument {input_1} {input_2} on line {i}")
                    sys.exit(-1)

            node = Node(OPCODES[operation], node_num, input_1, input_2)
            node_num += 1
            to_return.nodes.append(node)
            variables[args[0]].append(len(to_return.nodes)-1)

            if label:
                to_return.labels[label] = node
                label = None

        elif args[0].upper() in SPECIAL_OPCODES_NAMES:
            if len(args) != 2:
                l.error(f"Line {i} malformed")
                sys.exit(-1)

            node = Node(OPCODES[args[0].upper()], node_num, parse_arg(args[1]))
            node_num += 1
            to_return.nodes.append(node)
            if label:
                to_return.labels[label] = node
                label = None

        # Originally I wrote the next line only for BRR, then I realized that it also works for NTG (which I didn't consider).
        # Frankly the syntax is such that this can be generalized and cleaned up for any instruction, but I don't have time for that.
        elif args[3].upper() == 'BRR' or args[3].upper() == 'NTG':
            true_output = args[0].strip(',')
            false_output = args[1].strip(',')

            input_var = parse_arg(args[4])
            test_var = None
            if len(args) == 6:
                test_var = parse_arg(args[5])

            true_branch = Node(
                OPCODES['DUP'], node_num, None, None, None, None, True)
            node_num += 1
            to_return.nodes.append(true_branch)
            variables[true_output].append(len(to_return.nodes) - 1)

            false_branch = Node(
                OPCODES['DUP'], node_num, None, None, None, None, True)
            node_num += 1
            to_return.nodes.append(false_branch)
            variables[false_output].append(len(to_return.nodes) - 1)

            node = Node(OPCODES[args[3]], node_num, input_var, test_var, Destination(
                true_branch, INPUT_ONE), Destination(false_branch, INPUT_ONE))
            node_num += 1
            to_return.nodes.append(node)

            if label:
                to_return.labels[label] = node
                label = None

        else:
            l.error(f"unable to process line {line}")

    # at this point, we should have all variables defined and a node created for all instructions
    l.debug(f"to_return={to_return} variables={variables}")

    # Loop over all the nodes and fix up the inputs
    for node in to_return.nodes:
        for input_name, input_value in INPUTS:
            input = getattr(node, input_name)
            if isinstance(input, str):

                # _ is a placeholder that should not be treated as a variable
                if input == '_':
                    setattr(node, input_name, None)
                    continue

                # If the variable is a label, we'll need to replace
                # that at a later stage with the proper destination
                # name.
                elif input in to_return.labels:
                    continue

                # Variable, hook everything up properly
                setattr(node, input_name, None)
                for p in variables[input]:
                    parent = to_return.nodes[p]
                    target = 'destination_1'

                    if parent.destination_1 is not None:
                        target = 'destination_2'
                        if parent.destination_2 is not None:
                            # No more open spots on the parent, need to create a DUP node
                            new_dup = Node(
                                OPCODES['DUP'], node_num, None, None, parent.destination_2, None, True)
                            node_num += 1
                            parent.destination_2 = Destination(
                                new_dup, INPUT_ONE)
                            to_return.nodes.append(new_dup)
                            variables[input] = [len(to_return.nodes) - 1]
                            parent = new_dup

                    setattr(parent, target, Destination(node, input_value))

        # Need to check, if there is one literal left (and one
        # incoming edge), then by the ABI that literal needs to move
        # to input_1
        if node.opcode.num_inputs == 2 and (node.input_1 is None and node.input_2 is not None):
            node.input_1 = node.input_2
            node.input_2 = None

    # store the destination of all the externed symbols
    for extern in to_return.external_references.keys():
        if not extern in variables:
            l.debug("externed symbol {extern} is never assigned to, FYI.")
            continue

        for idx in variables[extern]:
            node = to_return.nodes[idx]
            assert(node.destination_1 == None)
            to_return.external_references[extern].append(node)

    l.debug(f"to_return={to_return}")
    return to_return


def optimize_graph(graph: Graph) -> Graph:
    """
    Perform a pass of the graph, removing any redundant DUP nodes that
    we added (which have Node.optimizable = True). A redundant DUP
    node is when a DUP node has only one output. In this case, the DUP
    node is superfulous and can be removed.
    """

    parents = collections.defaultdict(list)
    for node in graph.nodes:
        if node.destination_1:
            parents[node.destination_1.node].append(node)
        if node.destination_2:
            parents[node.destination_2.node].append(node)
    l.debug(f"parents={parents}")

    for node in list(graph.nodes):
        if node.opcode == OPCODES['DUP']:
            if len(parents[node]) == 1 and \
               node.destination_2 == None and \
               node.optimizable:

                l.debug(f"Found an optimizable node={node}")
                parent = parents[node][0]

                if parent.destination_1 and parent.destination_1.node == node:
                    parent.destination_1 = node.destination_1
                elif parent.destination_2 and parent.destination_2.node == node:
                    parent.destination_2 = node.destination_1
                else:
                    assert(False)

                l.debug(f"Removing node={node}")
                graph.nodes.remove(node)

    return graph


def graph_to_dot(graph: Graph, out: typing.TextIO):
    dot = graphviz.Digraph()

    node_to_labels = {v: k for (k, v) in graph.labels.items()}

    nodes_to_extern = {}
    for extern, nodes in graph.external_references.items():
        for node in nodes:
            nodes_to_extern[node] = extern

    visited = set()
    to_visit = collections.deque()
    for node in graph.nodes:
        to_visit.append(node)
        visited.add(node)
        if node in node_to_labels:
            name = f"[{node.id}] {node_to_labels[node]}: {node.opcode.repr}"
        else:
            name = f"[{node.id}] {node.opcode.repr}"

        dot.node(f"{node.id}", name)

    for extern in graph.external_references.keys():
        dot.node(extern, f"extern: {extern}")

    while len(to_visit) != 0:
        node = to_visit.popleft()

        for input_name, input_value in INPUTS:
            input = getattr(node, input_name)
            if input is not None:
                literal_id = f"{node.id}_{input}_{input_value}"
                dot.node(literal_id, f"{input}")
                dot.edge(literal_id, f"{node.id}")
        for destination_name in ['destination_1', 'destination_2']:
            destination = getattr(node, destination_name)
            if destination:
                if not destination.node in visited:
                    to_visit.append(destination.node)
                    visited.add(destination.node)
                    if destination.node in node_to_labels:
                        name = f"{node_to_labels[destination.node]}: {destination.node.opcode.repr}"
                    else:
                        name = f"{destination.node.opcode.repr}"
                    dot.node(destination.node.id, name)
                if node.opcode == OPCODES['BRR']:
                    direction = 'T' if destination_name == 'destination_1' else 'F'
                elif node.opcode == OPCODES['NTG']:
                    direction = 'new tag' if destination_name == 'destination_1' else 'old tag'
                else:
                    direction = 'L' if destination.input == INPUT_ONE else 'R'
                dot.edge(f"{node.id}", f"{destination.node.id}", label=f"{direction}")
        if node in nodes_to_extern:
            extern = nodes_to_extern[node]
            dot.edge(f"{node.id}", f"{extern}")

    out.write(dot.source)


def output_graph(f):
    constants, labels, external_references, exported = generate_header(f)
    instructions = unserialize_instructions(f)
    graph = instructions_to_graph(instructions, constants, labels, external_references, exported)
    graph = optimize_graph(graph)
    if (graph_output):
        with open(graph_output, 'w') as g:
            graph_to_dot(graph, g)


def main(input_file, output_file, graph_output):

    with open(input_file, 'rb') as input:
        output_graph(input)
        graph = parse_create_ir_graph(input)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="assembler")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debugging")
    parser.add_argument("--file", type=str, help="The file to assemble",
                        default=r"C:\Users\santo\Downloads\baby-a-fallen-lap-ray\os")
    parser.add_argument("--output", type=str,
                        help="Where to write the binary output.")
    parser.add_argument("--graph", type=str,
                        help="Where to write the graph dot output.")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    main(args.file, args.output or "output.bin", args.graph)
