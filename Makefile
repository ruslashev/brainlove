src = main.c
cflags = -Wall
lflags =
cc = gcc
bin = blove
objdir = .obj
objsubst = $(objdir)/%.o
obj = $(src:%=$(objsubst))

$(bin): $(obj)
	@echo "link $@"
	@$(cc) $< $(lflags) -o $@

$(objsubst): % | $(objdir)
	@echo "cc $<"
	@$(cc) $< $(cflags) -o $@ -c

$(objdir):
	@mkdir -p $(objdir)

clean:
	@echo "clean $(objdir)"
	@rm -rf $(objdir)

