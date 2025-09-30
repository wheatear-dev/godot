extends RefCounted

## Shadows builtin class `Key`
class Key extends RefCounted:
    pass

func test() -> void:
    var arr: Array[Key]
    arr.append(Key.new())
