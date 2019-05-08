import volatility.plugins.common as common
import volatility.utils as utils 
import volatility.win32 as win32
import volatility.plugins.filescan as filescan
import volatility.plugins.dumpfiles as filedump
from volatility.renderers.basic import Address

TASK_LOCATIONS = ['system32\\tasks']

class SchedTasks(common.AbstractWindowsCommand):

   def task_files(self, offset):
	addr_space = utils.load_as(self._config)
	file_list = []

	self._config.PHYSOFFSET = offset
	self._config.DUMP_DIR = "."
	dump_files = filedump.DumpFiles(self._config)
	dump_results = dump_files.calculate()

	for dump in dump_results:
		print dump.keys()
		print "[*] {0} : {1} : {2} : {3} : {4} : {5} : {6}".format(dump['name'],dump['ofpath'],dump['pid'],dump['fobj'], dump['pad'], dump['type'], dump['present'])

   def find_tasks(self):
	addr_space = utils.load_as(self._config)
	file_list=[]
	file_scan = filescan.FileScan(self._config)
	file_results = file_scan.calculate()

	for file in file_results:
		filename = str(file.file_name_with_device()).lower()
		address = Address(file.obj_offset)
		access_string = str(file.access_string())

		for task_location in TASK_LOCATIONS:
			if task_location in filename:
				if not "system32\\tasks\\microsoft" in filename:
					print address, filename, access_string
					offset = "0x{:x}".format(address)
					self.task_files(offset)

   def calculate(self):
	self.find_tasks()
