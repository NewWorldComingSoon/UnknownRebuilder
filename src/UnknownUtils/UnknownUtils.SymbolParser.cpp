#include <unknown/Symbol/SymbolParser.h>

#include "Symbol/PDB.h"
#include "Symbol/PDB_RawFile.h"
#include "Symbol/PDB_DBIStream.h"
#include "Symbol/PDB_InfoStream.h"
#include "Symbol/PDB_TPIStream.h"
#include "Symbol/PDB_NamesStream.h"
#include "Symbol/ExampleMemoryMappedFile.h"

#include <unordered_set>

namespace unknown {

namespace {
PDB_NO_DISCARD static bool
IsError(PDB::ErrorCode errorCode)
{
    switch (errorCode)
    {
    case PDB::ErrorCode::Success:
        return false;

    case PDB::ErrorCode::InvalidSuperBlock:
        printf("Invalid Superblock\n");
        return true;

    case PDB::ErrorCode::InvalidFreeBlockMap:
        printf("Invalid free block map\n");
        return true;

    case PDB::ErrorCode::InvalidStream:
        printf("Invalid stream\n");
        return true;

    case PDB::ErrorCode::InvalidSignature:
        printf("Invalid stream signature\n");
        return true;

    case PDB::ErrorCode::InvalidStreamIndex:
        printf("Invalid stream index\n");
        return true;

    case PDB::ErrorCode::UnknownVersion:
        printf("Unknown version\n");
        return true;
    }

    // only ErrorCode::Success means there wasn't an error, so all other paths have to assume there was an error
    return true;
}

PDB_NO_DISCARD static bool
HasValidDBIStreams(const PDB::RawFile &rawPdbFile, const PDB::DBIStream &dbiStream)
{
    // check whether the DBI stream offers all sub-streams we need
    if (IsError(dbiStream.HasValidImageSectionStream(rawPdbFile)))
    {
        return false;
    }

    if (IsError(dbiStream.HasValidPublicSymbolStream(rawPdbFile)))
    {
        return false;
    }

    if (IsError(dbiStream.HasValidGlobalSymbolStream(rawPdbFile)))
    {
        return false;
    }

    if (IsError(dbiStream.HasValidSectionContributionStream(rawPdbFile)))
    {
        return false;
    }

    return true;
}
} // namespace

class SymbolParserByPDB : public SymbolParser
{
public:
    SymbolParserByPDB() : SymbolParser() {}
    ~SymbolParserByPDB() = default;

private:
    void ExampleFunctionSymbols(const PDB::RawFile &rawPdbFile, const PDB::DBIStream &dbiStream)
    {
        const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);

        // prepare the module info stream for grabbing function symbols from modules
        const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(rawPdbFile);

        // prepare symbol record stream needed by the public stream
        const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawPdbFile);

        // note that we only use unordered_set in order to keep the example code easy to understand.
        // using other hash set implementations like e.g. abseil's Swiss Tables
        // (https://abseil.io/about/design/swisstables) is *much* faster.
        std::vector<FunctionSymbol> functionSymbols;
        std::unordered_set<uint32_t> seenFunctionRVAs;

        // start by reading the module stream, grabbing every function symbol we can find.
        // in most cases, this gives us ~90% of all function symbols already, along with their size.
        {
            const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();

            for (const PDB::ModuleInfoStream::Module &module : modules)
            {
                if (!module.HasSymbolStream())
                {
                    continue;
                }

                const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawPdbFile);
                moduleSymbolStream.ForEachSymbol([&functionSymbols, &seenFunctionRVAs, &imageSectionStream](
                                                     const PDB::CodeView::DBI::Record *record) {
                    // only grab function symbols from the module streams
                    const char *name = nullptr;
                    uint32_t rva = 0u;
                    uint32_t size = 0u;
                    if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_FRAMEPROC)
                    {
                        // functionSymbols[functionSymbols.size() - 1].frameProc = record;
                        functionSymbols[functionSymbols.size() - 1].cbFrame = record->data.S_FRAMEPROC.cbFrame;
                        functionSymbols[functionSymbols.size() - 1].cbPad = record->data.S_FRAMEPROC.cbPad;
                        functionSymbols[functionSymbols.size() - 1].offPad = record->data.S_FRAMEPROC.offPad;
                        functionSymbols[functionSymbols.size() - 1].cbSaveRegs = record->data.S_FRAMEPROC.cbSaveRegs;
                        functionSymbols[functionSymbols.size() - 1].offExHdlr = record->data.S_FRAMEPROC.offExHdlr;
                        functionSymbols[functionSymbols.size() - 1].sectExHdlr = record->data.S_FRAMEPROC.sectExHdlr;

                        functionSymbols[functionSymbols.size() - 1].hasAlloca =
                            record->data.S_FRAMEPROC.flags.fHasAlloca ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasSetJmp =
                            record->data.S_FRAMEPROC.flags.fHasSetJmp ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasLongJmp =
                            record->data.S_FRAMEPROC.flags.fHasLongJmp ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasInlAsm =
                            record->data.S_FRAMEPROC.flags.fHasInlAsm ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasEH =
                            record->data.S_FRAMEPROC.flags.fHasEH ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasSEH =
                            record->data.S_FRAMEPROC.flags.fHasSEH ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasNaked =
                            record->data.S_FRAMEPROC.flags.fNaked ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasSecurityChecks =
                            record->data.S_FRAMEPROC.flags.fSecurityChecks ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasAsyncEH =
                            record->data.S_FRAMEPROC.flags.fAsyncEH ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasWasInlined =
                            record->data.S_FRAMEPROC.flags.fWasInlined ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasGSCheck =
                            record->data.S_FRAMEPROC.flags.fGSCheck ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasSafeBuffers =
                            record->data.S_FRAMEPROC.flags.fSafeBuffers ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasOptSpeed =
                            record->data.S_FRAMEPROC.flags.fOptSpeed ? true : false;

                        functionSymbols[functionSymbols.size() - 1].hasGuardCF =
                            record->data.S_FRAMEPROC.flags.fGuardCF ? true : false;
                        return;
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32)
                    {
                        if (record->data.S_THUNK32.thunk == PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental)
                        {
                            // we have never seen incremental linking thunks stored inside a S_THUNK32 symbol, but
                            // better safe than sorry
                            name = "ILT";
                            rva = imageSectionStream.ConvertSectionOffsetToRVA(
                                record->data.S_THUNK32.section, record->data.S_THUNK32.offset);
                            size = 5u;
                        }
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE)
                    {
                        // incremental linking thunks are stored in the linker module
                        name = "ILT";
                        rva = imageSectionStream.ConvertSectionOffsetToRVA(
                            record->data.S_TRAMPOLINE.thunkSection, record->data.S_TRAMPOLINE.thunkOffset);
                        size = 5u;
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32)
                    {
                        name = record->data.S_LPROC32.name;
                        rva = imageSectionStream.ConvertSectionOffsetToRVA(
                            record->data.S_LPROC32.section, record->data.S_LPROC32.offset);
                        size = record->data.S_LPROC32.codeSize;
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32)
                    {
                        name = record->data.S_GPROC32.name;
                        rva = imageSectionStream.ConvertSectionOffsetToRVA(
                            record->data.S_GPROC32.section, record->data.S_GPROC32.offset);
                        size = record->data.S_GPROC32.codeSize;
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID)
                    {
                        name = record->data.S_LPROC32_ID.name;
                        rva = imageSectionStream.ConvertSectionOffsetToRVA(
                            record->data.S_LPROC32_ID.section, record->data.S_LPROC32_ID.offset);
                        size = record->data.S_LPROC32_ID.codeSize;
                    }
                    else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID)
                    {
                        name = record->data.S_GPROC32_ID.name;
                        rva = imageSectionStream.ConvertSectionOffsetToRVA(
                            record->data.S_GPROC32_ID.section, record->data.S_GPROC32_ID.offset);
                        size = record->data.S_GPROC32_ID.codeSize;
                    }

                    if (rva == 0u)
                    {
                        return;
                    }

                    functionSymbols.push_back(FunctionSymbol{name, rva, size});
                    seenFunctionRVAs.emplace(rva);
                });
            }
        }

        // we don't need to touch global symbols in this case.
        // most of the data we need can be obtained from the module symbol streams, and the global symbol stream only
        // offers data symbols on top of that, which we are not interested in. however, there can still be public
        // function symbols we haven't seen yet in any of the modules, especially for PDBs that don't provide
        // module-specific information.

        // read public symbols

        const PDB::PublicSymbolStream publicSymbolStream = dbiStream.CreatePublicSymbolStream(rawPdbFile);
        {
            const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();
            const size_t count = hashRecords.GetLength();

            for (const PDB::HashRecord &hashRecord : hashRecords)
            {
                const PDB::CodeView::DBI::Record *record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
                if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
                     PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u)
                {
                    // ignore everything that is not a function
                    continue;
                }

                const uint32_t rva = imageSectionStream.ConvertSectionOffsetToRVA(
                    record->data.S_PUB32.section, record->data.S_PUB32.offset);
                if (rva == 0u)
                {
                    // certain symbols (e.g. control-flow guard symbols) don't have a valid RVA, ignore those
                    continue;
                }

                // check whether we already know this symbol from one of the module streams
                const auto it = seenFunctionRVAs.find(rva);
                if (it != seenFunctionRVAs.end())
                {
                    // we know this symbol already, ignore it
                    continue;
                }

                // this is a new function symbol, so store it.
                // note that we don't know its size yet.
                functionSymbols.push_back(FunctionSymbol{record->data.S_PUB32.name, rva, 0u});
            }
        }

        // we still need to find the size of the public function symbols.
        // this can be deduced by sorting the symbols by their RVA, and then computing the distance between the current
        // and the next symbol. this works since functions are always mapped to executable pages, so they aren't
        // interleaved by any data symbols.
        std::sort(
            functionSymbols.begin(), functionSymbols.end(), [](const FunctionSymbol &lhs, const FunctionSymbol &rhs) {
                return lhs.rva < rhs.rva;
            });

        const size_t symbolCount = functionSymbols.size();
        if (symbolCount != 0u)
        {
            size_t foundCount = 0u;

            // we have at least 1 symbol.
            // compute missing symbol sizes by computing the distance from this symbol to the next.
            // note that this includes "int 3" padding after the end of a function. if you don't want that, but the
            // actual number of bytes of the function's code, your best bet is to use a disassembler instead.
            for (size_t i = 0u; i < symbolCount - 1u; ++i)
            {
                FunctionSymbol &currentSymbol = functionSymbols[i];
                if (currentSymbol.size != 0u)
                {
                    // the symbol's size is already known
                    continue;
                }

                const FunctionSymbol &nextSymbol = functionSymbols[i + 1u];
                const size_t size = nextSymbol.rva - currentSymbol.rva;
                (void)size; // unused
                ++foundCount;
            }

            // we know have the sizes of all symbols, except the last.
            // this can be found by going through the contributions, if needed.
            FunctionSymbol &lastSymbol = functionSymbols[symbolCount - 1u];
            if (lastSymbol.size != 0u)
            {
                // bad luck, we can't deduce the last symbol's size, so have to consult the contributions instead.
                // we do a linear search in this case to keep the code simple.
                const PDB::SectionContributionStream sectionContributionStream =
                    dbiStream.CreateSectionContributionStream(rawPdbFile);
                const PDB::ArrayView<PDB::DBI::SectionContribution> sectionContributions =
                    sectionContributionStream.GetContributions();
                for (const PDB::DBI::SectionContribution &contribution : sectionContributions)
                {
                    const uint32_t rva =
                        imageSectionStream.ConvertSectionOffsetToRVA(contribution.section, contribution.offset);
                    if (rva == 0u)
                    {
                        printf("Contribution has invalid RVA\n");
                        continue;
                    }

                    if (rva == lastSymbol.rva)
                    {
                        lastSymbol.size = contribution.size;
                        break;
                    }

                    if (rva > lastSymbol.rva)
                    {
                        // should have found the contribution by now
                        printf(
                            "Unknown contribution for symbol %s at RVA 0x%X", lastSymbol.name.c_str(), lastSymbol.rva);
                        break;
                    }
                }
            }
        }

        if (!functionSymbols.empty())
        {
            std::swap(mFunctionSymbols, functionSymbols);
        }
    }

public:
    // Parser
    virtual bool ParseAllSymbols(StringRef SymFilePath) override
    {
        // Not implemented
        return false;
    }

    virtual bool ParseFunctionSymbols(StringRef SymFilePath) override
    {
        // try to open the PDB file and check whether all the data we need is available
        MemoryMappedFile::Handle pdbFile = MemoryMappedFile::Open(SymFilePath.data());
        if (!pdbFile.baseAddress)
        {
            return false;
        }

        if (IsError(PDB::ValidateFile(pdbFile.baseAddress)))
        {
            MemoryMappedFile::Close(pdbFile);
            return false;
        }

        const PDB::RawFile rawPdbFile = PDB::CreateRawFile(pdbFile.baseAddress);
        if (IsError(PDB::HasValidDBIStream(rawPdbFile)))
        {
            MemoryMappedFile::Close(pdbFile);
            return false;
        }

        const PDB::InfoStream infoStream(rawPdbFile);
        if (infoStream.UsesDebugFastLink())
        {
            printf("PDB was linked using unsupported option /DEBUG:FASTLINK\n");

            MemoryMappedFile::Close(pdbFile);
            return false;
        }

        const auto h = infoStream.GetHeader();
        const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawPdbFile);
        if (!HasValidDBIStreams(rawPdbFile, dbiStream))
        {
            MemoryMappedFile::Close(pdbFile);
            return false;
        }

        const PDB::TPIStream tpiStream = PDB::CreateTPIStream(rawPdbFile);
        if (PDB::HasValidTPIStream(rawPdbFile) != PDB::ErrorCode::Success)
        {
            MemoryMappedFile::Close(pdbFile);
            return false;
        }

        ExampleFunctionSymbols(rawPdbFile, dbiStream);

        MemoryMappedFile::Close(pdbFile);

        return true;
    }
};

} // namespace unknown
