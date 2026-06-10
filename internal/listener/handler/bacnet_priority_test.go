package handler

import "testing"

func TestBACnetPriorityOverride(t *testing.T) {
	// priorityArray target: propertyIdentifier context tag [1] len 1 = 0x19 0x57 (87).
	if _, ok := bacnetPriorityOverride([]byte{0x00, 0x0f, 0x0c, 0x00, 0x19, 0x57}); !ok {
		t.Error("priorityArray (0x19 0x57) not detected")
	}
	// explicit high command-priority: context tag [4] len 1 = 0x49 0x01 (priority 1).
	pri, ok := bacnetPriorityOverride([]byte{0x49, 0x01})
	if !ok || pri != 1 {
		t.Errorf("priority-1 write not detected: pri=%d ok=%v", pri, ok)
	}
	// an ordinary present-value write without priority must not trip it.
	if _, ok := bacnetPriorityOverride([]byte{0x19, 0x55, 0x3e, 0x44, 0x42, 0x28, 0x00, 0x00, 0x3f}); ok {
		t.Error("plain present-value write wrongly flagged as priority override")
	}
}
