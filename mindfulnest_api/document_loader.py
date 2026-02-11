"""
Document loader and vector store builder
Automatically creates FAISS index if it doesn't exist
"""
from pathlib import Path
from langchain_community.document_loaders import PyPDFLoader, WebBaseLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from .config import Config
from .logger import setup_logger

logger = setup_logger("document_loader")


class DocumentLoader:
    """Handles document loading and vector store creation"""

    # PDF Sources
    PDF_SOURCES = [
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/MHGuidebook-EBookDownload.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/d17868e7-8165-473a-ae4b-9dd098fbbd53.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/Effects_of_Excessive_Screen_Time_on_Child_Developm.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/Effects-on-Health.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/EffectsofExcessiveScreenTimeonNeurodevelopmentLearningMemoryMentalHealthandNeurodegeneration-aScopingReviewNeophytouE.ManwellL.A.EikelboomR.2019..pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/obesity.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/overall_well_being.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/relation_btw_genz_and_screentime_anxiety.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/Screen_Time_Activities_and_Aggressive_Behaviors_Am.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/screen_time.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/screentime.pdf",
        "https://wellbeingdata.s3.ap-south-1.amazonaws.com/wellbeing.PDF"
    ]

    # Web Sources
    WEB_SOURCES = [
        "https://www.healthline.com/health/anxiety/social-anxiety-treatment",
        "https://www.nhs.uk/mental-health/conditions/social-anxiety/",
        "https://www.todaysparent.com/family/parenting/heres-why-screens-bring-out-the-worst-in-your-kid/",
        "https://www.healthline.com/health/adhd/10-tips-for-helping-kids-with-adhd-manage-screen-time",
        "https://www.indiatoday.in/health/story/screen-addiction-causing-rise-in-adhd-among-children-in-india-2617840-2024-10-16",
        "https://www.nhs.uk/mental-health/self-help/guides-tools-and-activities/five-steps-to-mental-wellbeing/",
        "https://www.voasw.org/blog/what-is-mental-wellness-how-to-improve-it/",
        "https://www.webmd.com/depression/depression-or-anxiety",
        "https://www.who.int/news-room/fact-sheets/detail/depression",
        "https://www.betterhealth.vic.gov.au/health/conditionsandtreatments/anxiety-and-depression-in-men#bhc-content",
        "https://www.betterhealth.vic.gov.au/health/conditionsandtreatments/cognitive-behaviour-therapy",
        "https://www.betterhealth.vic.gov.au/health/conditionsandtreatments/depression-treatment-and-management",
        "https://my.clevelandclinic.org/health/diseases/9536-anxiety-disorders",
        "https://www.calm.com/blog/how-to-be-happy-again",
        "https://www.health.harvard.edu/blog/how-can-you-find-joy-or-at-least-peace-during-difficult-times-202210062826",
        "https://www.thedimplelife.com/self-growth/100-ways-to-add-more-joy-into-your-life/",
        "https://hbr.org/2021/09/rediscover-joy-at-work",
        "https://jeannenangle.com/how-to-find-joy-again-10-best-tips-for-a-happy-heart",
        "https://www.allprodad.com/10-ways-to-bring-joy-into-your-life/",
        "https://hbr.org/2015/05/signs-that-youre-being-too-stubborn",
        "https://www.psychologs.com/the-psychology-behind-stubbornness/?srsltid=AfmBOoo9LzHkr00dyrjPX5Z-gTPJr_bJ_-BTuuccAtRmTX47EJJfjdR3",
        "https://www.betterhelp.com/advice/general/turning-bad-mad-and-stubborn-into-positive-personality-traits/",
        "https://www.potsdam.edu/studentlife/wellness/counseling-center/what-does-screen-time-do-my-brain",
        "https://hms.harvard.edu/news/screen-time-brain",
        "https://www.careinsurance.com/blog/health-insurance-articles/impact-of-excessive-screen-time-on-your-child-s-mental-health",
        "https://www.scripps.org/news_items/6310-8-tips-to-reduce-screen-time-for-adults",
        "https://www.coursera.org/in/articles/time-management",
        "https://extension.uga.edu/publications/detail.html?number=C1042&title=time-management-10-strategies-for-better-time-management",
        "https://namica.org/blog/tips-on-managing-your-screen-time-for-good-mental-health/",
        "https://www.mywellnesshub.in/blog/how-to-create-a-screen-time-schedule-that-actually-works/",
        "https://www.brunet.ca/en/health/health-tips/managing-screen-time/",
        "https://www.unicef.org/parenting/mental-health/3-ways-help-teens-manage-screen-time",
        "https://www.mykidsvision.org/knowledge-centre/screen-time-in-teenagers-how-can-we-manage-it",
        "https://health.choc.org/how-to-limit-screen-time-for-teenagers/",
        "https://www.unicef.org/parenting/mental-health/social-media-teens",
        "https://www.yourhourapp.com/blog/screen-time-control-screen-time-tracker-procrastination-ways-overcome-it-6",
        "https://www.yourhourapp.com/blog/screen-time-app-mobile-addiction-control-app-three-ways-manage-your-time-7",
        "https://www.yourhourapp.com/blog/screen-time-helper-screen-time-app-difference-between-average-success-9",
        "https://www.yourhourapp.com/blog/phone-addiction-controller-screen-time-app-usage-tracker-mindfulness-productivity-4",
        "https://www.yourhourapp.com/blog/screen-time-tracker-phone-timer-lock-app-boredom-creativity-art-doing-nothing-12",
        "https://www.yourhourapp.com/blog/phone-timer-lock-app-phone-addiction-controller-phone-addiction-2",
        "https://www.yourhourapp.com/blog/screen-time-app-usage-tracker-screentime-for-kids-office-away-office-8",
        "https://www.yourhourapp.com/blog/screen-time-parental-control-screen-time-helper-young-vs-old-smart-phones-seperating-generations-10",
        "https://www.yourhourapp.com/blog/yourhour-screentime-app-screen-time-tracker-mobile-addiction-show-behind-11"
    ]

    @staticmethod
    def load_documents():
        """Load all documents from PDFs and web sources"""
        logger.info("Starting document loading...")

        all_pages = []
        pdf_success = 0
        web_success = 0

        # Load PDFs
        logger.info(f"Loading {len(DocumentLoader.PDF_SOURCES)} PDFs...")
        for pdf_url in DocumentLoader.PDF_SOURCES:
            try:
                loader = PyPDFLoader(pdf_url)
                pages = loader.load()
                all_pages.extend(pages)
                pdf_success += 1
            except Exception as e:
                logger.warning(f"Failed to load PDF {pdf_url[:50]}: {str(e)[:100]}")

        logger.info(f"Loaded {pdf_success}/{len(DocumentLoader.PDF_SOURCES)} PDFs")

        # Load web pages
        logger.info(f"Loading {len(DocumentLoader.WEB_SOURCES)} web pages...")
        for web_url in DocumentLoader.WEB_SOURCES:
            try:
                loader = WebBaseLoader(web_url)
                pages = loader.load()
                all_pages.extend(pages)
                web_success += 1
            except Exception as e:
                logger.warning(f"Failed to load web page {web_url[:50]}: {str(e)[:100]}")

        logger.info(f"Loaded {web_success}/{len(DocumentLoader.WEB_SOURCES)} web pages")
        logger.info(f"Total pages loaded: {len(all_pages)}")

        if len(all_pages) == 0:
            raise ValueError("No documents loaded! Check internet connection and sources.")

        return all_pages

    @staticmethod
    def chunk_documents(documents):
        """Split documents into chunks"""
        logger.info("Chunking documents...")

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=Config.CHUNK_SIZE,
            chunk_overlap=Config.CHUNK_OVERLAP,
            length_function=len
        )

        chunks = splitter.split_documents(documents)
        logger.info(f"Created {len(chunks)} chunks")

        return chunks

    @staticmethod
    def create_vector_store(chunks, embeddings):
        """Create FAISS vector store from chunks"""
        logger.info("Creating FAISS vector store...")

        vectorstore = FAISS.from_documents(chunks, embeddings)
        logger.info("Vector store created successfully")

        return vectorstore

    @staticmethod
    def build_and_save_index():
        """Complete pipeline: load documents, chunk, create index, save"""
        logger.info("=" * 60)
        logger.info("BUILDING VECTOR STORE FROM SCRATCH")
        logger.info("=" * 60)

        try:
            # Load documents
            documents = DocumentLoader.load_documents()

            # Chunk documents
            chunks = DocumentLoader.chunk_documents(documents)

            # Create embeddings
            logger.info("Initializing embeddings...")
            embeddings = OpenAIEmbeddings(model=Config.EMBEDDING_MODEL)

            # Create vector store
            vectorstore = DocumentLoader.create_vector_store(chunks, embeddings)

            # Save to disk
            logger.info(f"Saving index to {Config.INDEX_PATH}...")
            Config.INDEX_PATH.mkdir(exist_ok=True)
            vectorstore.save_local(str(Config.INDEX_PATH))

            logger.info("=" * 60)
            logger.info("✅ VECTOR STORE BUILT AND SAVED SUCCESSFULLY")
            logger.info("=" * 60)

            return vectorstore

        except Exception as e:
            logger.error(f"Failed to build vector store: {e}", exc_info=True)
            raise
