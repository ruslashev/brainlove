src = main.c
cflags = -Wall -g
lflags =
cc = gcc
bin = blove
objdir = .obj
objsubst = $(objdir)/%.o
obj = $(src:%=$(objsubst))

test: $(bin)
	./$(bin) examples/hello-world.bf

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

