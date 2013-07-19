all: test_role_graph.pdf

%.pdf: %.dot
	dot $< -T pdf -o $*.pdf
