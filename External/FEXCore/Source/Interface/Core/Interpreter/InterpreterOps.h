namespace FEXCore::Core {
    struct InternalThreadState;
}

namespace FEXCore::IR {
    class IRListView;
}

namespace FEXCore::Core{
    struct DebugData;
}

namespace FEXCore::CPU {
    class InterpreterOps {
        public:
        static void InterpretIR(FEXCore::Core::InternalThreadState *Thread, FEXCore::IR::IRListView *CurrentIR, FEXCore::Core::DebugData *DebugData);
    };
};