; ModuleID = 'struct.c'
source_filename = "struct.c"
target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.15.0"

%struct.ThreeInts = type { i32, i32, i32 }

; Function Attrs: noinline nounwind optnone ssp uwtable
define void @called(%struct.ThreeInts*) #0 {
  %2 = alloca %struct.ThreeInts*, align 8
  store %struct.ThreeInts* %0, %struct.ThreeInts** %2, align 8
  %3 = load %struct.ThreeInts*, %struct.ThreeInts** %2, align 8
  %4 = getelementptr inbounds %struct.ThreeInts, %struct.ThreeInts* %3, i32 0, i32 0
  %5 = load i32, i32* %4, align 4
  %6 = load %struct.ThreeInts*, %struct.ThreeInts** %2, align 8
  %7 = getelementptr inbounds %struct.ThreeInts, %struct.ThreeInts* %6, i32 0, i32 2
  store i32 %5, i32* %7, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone ssp uwtable
define i32 @caller(i32) #0 {
  %2 = alloca i32, align 4
  %3 = alloca %struct.ThreeInts, align 4
  store i32 %0, i32* %2, align 4
  %4 = bitcast %struct.ThreeInts* %3 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 4 %4, i8 0, i64 12, i1 false)
  %5 = load i32, i32* %2, align 4
  %6 = getelementptr inbounds %struct.ThreeInts, %struct.ThreeInts* %3, i32 0, i32 0
  store i32 %5, i32* %6, align 4
  call void @called(%struct.ThreeInts* %3)
  %7 = getelementptr inbounds %struct.ThreeInts, %struct.ThreeInts* %3, i32 0, i32 2
  %8 = load i32, i32* %7, align 4
  ret i32 %8
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #1

attributes #0 = { noinline nounwind optnone ssp uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="penryn" "target-features"="+cx16,+cx8,+fxsr,+mmx,+sahf,+sse,+sse2,+sse3,+sse4.1,+ssse3,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{!"clang version 9.0.1 "}
