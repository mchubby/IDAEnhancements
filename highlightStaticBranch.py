# Based on https://github.com/eschweiler/IDAEnhancements/blob/master/InitialAnalysis.py
# ============================================================================
# Copyright (c) 2012, Sebastian Eschweiler <advanced(dot)malware<dot>analyst[at]gmail.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =============================================================================


import idaapi, idautils, idc

COLOR_CALL = 0xffffd0
call_instructions = [idaapi.MIPS_b, idaapi.MIPS_j, idaapi.MIPS_jal, idaapi.MIPS_jalr]

COLOR_BRANCH = 0xffd0ff
branch_instructions = [idaapi.MIPS_bgez, idaapi.MIPS_bgezal, idaapi.MIPS_bgezall, idaapi.MIPS_bgezl, idaapi.MIPS_bgtz, idaapi.MIPS_bgtzl, idaapi.MIPS_blez, idaapi.MIPS_blezl, idaapi.MIPS_bltz, idaapi.MIPS_bltzal, idaapi.MIPS_bltzall, idaapi.MIPS_bltzl, idaapi.MIPS_beq, idaapi.MIPS_beql, idaapi.MIPS_bne, idaapi.MIPS_bnel, idaapi.MIPS_bnez, idaapi.MIPS_bnezl, idaapi.MIPS_beqz, idaapi.MIPS_beqzl]

COLOR_RET = 0xffd0ff
ret_instructions = [idaapi.MIPS_jr]

def colorize(addr, color):
	idaapi.set_item_color(addr, color)

def iterateInstructions():
	next = 0
	while next != idaapi.BADADDR:

		# get next instruction
		next = idc.NextHead(next)

		idaapi.decode_insn(next)
		if idaapi.cmd.itype in call_instructions:
			colorize(idaapi.cmd.ea, COLOR_CALL)

		if idaapi.cmd.itype in branch_instructions:
			colorize(idaapi.cmd.ea, COLOR_BRANCH)

		if idaapi.cmd.itype in ret_instructions:
			colorize(idaapi.cmd.ea, COLOR_RET)

iterateInstructions()

# refresh ida view to display our results
idaapi.refresh_idaview_anyway()

print "done. have a nice day :-)"
