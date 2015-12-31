
INCLUDE = /usr/local/include
LIBS = -pthread -lboost_program_options
LIBPATH = /usr/local/lib
OBJS = main.o 

.cc.o:
	c++ -g -I$(INCLUDE) -c $<

NXCore_kw: $(OBJS)
	c++ -L$(LIBPATH) $(LIBS) -o NXCore_kw $(OBJS) 

clean:
	rm -f *.o NXCore_kw
