DWORD WINAPI enum_stack_thread(LPVOID lpParam)
{
	t_stack_enum_params* args = static_cast<t_stack_enum_params*>(lpParam);
	if (!args || !args->c || !args->ctx) {
		return STATUS_INVALID_PARAMETER;
	}
	size_t fetched = 0;
	bool in_shc = false;
	const pesieve::thread_ctx& c = *(args->c);
#ifdef _WIN64
        if (c.is64b) {

          fetched = peconv::read_remote_memory(args->hProcess, (PVOID)c.rsp,
                                               (BYTE*)args->StackUnwindResult64,
                                               sizeof(args->StackUnwindResult64));
        }
#endif
        if (!c.is64b) { //32bit process
          for (int i = 0; i < args->_CaptureSize*args->scale; i++) {
            fetched = peconv::read_remote_memory(
                args->hProcess, (PVOID)(c.rsp+i*sizeof(ULONG32)), (BYTE*)&args->StackUnwindResult64[i],
                sizeof(ULONG32));
			
		  }
        }



	if (fetched) {
		args->is_ok = true;
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}
