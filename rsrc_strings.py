"""
    rsrc_strings.py
    Author: nibble <@develsec.org>
    Description: Script to automatically comment out rsrc strings in disasm
    Depends: idapython, pefile
"""

import pefile
import ctypes

print 'Analyzing PE...'
filename = GetInputFile()
pe =  pefile.PE(filename)
rt_string_idx = [
    entry.id for entry in 
    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])
rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

def ResolveStr(opnd):
    for entry in rt_string_directory.directory.entries:
        if entry.directory.strings.has_key(opnd):
            return entry.directory.strings[opnd].strip().replace('\n','\\n')
    return 'unknown'

print 'Looking for uID\'s...'
for seg_ea in Segments():
    for head in Heads(seg_ea, SegEnd(seg_ea)):
        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            cmt = Comment(head)
            opndt = GetOpType(head, 0)
            if mnem == 'push' and cmt == 'uID' and opndt == o_imm:
                opnd = GetOperandValue(head, 0)
                rstr = ResolveStr(opnd)
                MakeComm(head, ctypes.c_char_p(cmt+' "'+rstr+'"').value)
                print '%x: %s ; %s -> %s' % (head, opnd, cmt, rstr)

print 'All done...'
