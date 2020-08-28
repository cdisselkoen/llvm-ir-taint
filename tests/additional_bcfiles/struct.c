struct TwoInts {
  int el0;
  int el1;
};

void called(struct TwoInts* ti) {
  ti->el1 = ti->el0;
}

int caller(int x) {
  struct TwoInts ti = { 0 };
  ti.el0 = x;
  called(&ti);
  return ti.el1;
}
